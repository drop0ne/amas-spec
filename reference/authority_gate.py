#!/usr/bin/env python3
"""AMAS AAB reference authorization gate.

Evaluates structured action requests against an explicit authority lease.
This module never executes the requested action.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SIDE_EFFECT = {
    "observe": 0,
    "simulate": 1,
    "reversible_write": 2,
    "persistent_write": 3,
    "privileged_change": 4,
}


def canonical_hash(obj: Any) -> str:
    raw = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def parse_time(value: str) -> datetime:
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        raise ValueError("timestamps must include timezone")
    return dt.astimezone(timezone.utc)


def _outcome(policy: dict[str, Any], hard: bool) -> str:
    if hard:
        return "DENY"
    return "ESCALATE" if policy.get("operator_escalation", False) else "DENY"


def evaluate(policy: dict[str, Any], request: dict[str, Any], now: datetime | None = None) -> dict[str, Any]:
    """Return an auditable decision receipt. Fail closed on malformed input."""
    now = now or datetime.now(timezone.utc)
    checks: list[tuple[str, bool, bool]] = []

    try:
        expires = parse_time(policy["expires_at"])
        checks.append(("policy_freshness", now <= expires, True))
        checks.append(("principal_binding", request["principal"] == policy["principal"], True))
        checks.append(("objective_binding", request["objective_id"] in policy["objectives"], False))
        checks.append(("operation_scope", request["operation"] in policy["operations"], False))
        checks.append(("target_scope", request["target"] in policy["targets"], False))

        destination = request.get("destination")
        checks.append(("destination_scope", destination is None or destination in policy.get("destinations", []), False))

        credential = request.get("credential_ref")
        checks.append(("credential_scope", credential is None or credential in policy.get("credentials", []), True))

        req_effect = SIDE_EFFECT[request["side_effect"]]
        max_effect = SIDE_EFFECT[policy["max_side_effect"]]
        checks.append(("side_effect_ceiling", req_effect <= max_effect, True))

        budgets = policy["budgets"]
        usage = request["usage"]
        checks.append(("action_budget", usage["actions"] <= budgets["max_actions"], True))
        checks.append(("network_budget", usage["network_calls"] <= budgets["max_network_calls"], True))
        checks.append(("egress_budget", usage["egress_bytes"] <= budgets["max_egress_bytes"], True))
        checks.append(("wall_clock_budget", usage["wall_clock_seconds"] <= budgets["max_wall_clock_seconds"], True))
        checks.append(("delegation_depth", request.get("delegation_depth", 0) <= policy.get("max_delegation_depth", 0), True))

        failed = next(((name, hard) for name, ok, hard in checks if not ok), None)
        if failed:
            reason, hard = failed
            decision = _outcome(policy, hard)
        else:
            reason, decision = "authorized", "ALLOW"
    except (KeyError, TypeError, ValueError) as exc:
        reason, decision = f"invalid_request:{type(exc).__name__}", "DENY"

    return {
        "request_id": request.get("request_id", "UNKNOWN"),
        "policy_id": policy.get("policy_id", "UNKNOWN"),
        "decision": decision,
        "reason": reason,
        "evaluated_at": now.isoformat().replace("+00:00", "Z"),
        "policy_hash": canonical_hash(policy),
        "request_hash": canonical_hash(request),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate AMAS AAB action requests")
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--requests", required=True, type=Path)
    args = parser.parse_args()

    policy = json.loads(args.policy.read_text(encoding="utf-8"))
    requests = json.loads(args.requests.read_text(encoding="utf-8"))
    if isinstance(requests, dict):
        requests = [requests]

    for request in requests:
        print(json.dumps(evaluate(policy, request), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
