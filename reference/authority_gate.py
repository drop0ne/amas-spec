#!/usr/bin/env python3
"""AMAS AAB reference authorization gate.

Evaluates structured action requests against an explicit authority policy. This
module never executes the requested action. The public validation helpers are
shared by the broker and delegation code so schema-shaped authority objects do
not acquire different meanings in different runtime components.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from canonical_json import CanonicalJSONError, MAX_SAFE_INTEGER, sha256 as canonical_sha256, validate as validate_canonical

SIDE_EFFECT = {
    "observe": 0,
    "simulate": 1,
    "reversible_write": 2,
    "persistent_write": 3,
    "privileged_change": 4,
}

_POLICY_REQUIRED = {"policy_id", "principal", "objectives", "operations", "targets", "max_side_effect", "budgets", "expires_at"}
_POLICY_OPTIONAL = {"destinations", "credentials", "capability_contracts", "max_delegation_depth", "operator_escalation"}
_PARENT_POLICY_ALLOWED = _POLICY_REQUIRED | _POLICY_OPTIONAL
_CHILD_BINDING_FIELDS = {"parent_policy_id", "parent_policy_hash"}
_CHILD_POLICY_REQUIRED = _POLICY_REQUIRED | _CHILD_BINDING_FIELDS
_CHILD_POLICY_ALLOWED = _CHILD_POLICY_REQUIRED | _POLICY_OPTIONAL
_REQUEST_REQUIRED = {"request_id", "principal", "objective_id", "operation", "target", "side_effect", "usage", "timestamp"}
_REQUEST_ALLOWED = _REQUEST_REQUIRED | {"destination", "credential_ref", "capability_contract_id", "delegation_depth"}
_USAGE_KEYS = {"actions", "network_calls", "egress_bytes", "wall_clock_seconds"}
_BUDGET_KEYS = {"max_actions", "max_network_calls", "max_egress_bytes", "max_wall_clock_seconds"}
_CONTRACT_ID_RE = re.compile(r"^cap-sha256:[0-9a-f]{64}$")
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")


def canonical_hash(obj: Any) -> str:
    return canonical_sha256(obj)


def safe_diagnostic_hash(obj: Any) -> str:
    try:
        return canonical_hash(obj)
    except (CanonicalJSONError, TypeError, ValueError, RecursionError):
        raw = repr(obj).encode("utf-8", errors="backslashreplace")
        return hashlib.sha256(b"INVALID-CANONICAL-JSON-V1\x00" + raw).hexdigest()


def parse_time(value: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise ValueError("timestamp must be a non-empty string")
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError("invalid date-time") from exc
    if dt.tzinfo is None:
        raise ValueError("timestamps must include timezone")
    return dt.astimezone(timezone.utc)


def _require_shape(obj: dict[str, Any], required: set[str], allowed: set[str], name: str) -> None:
    missing = sorted(required - set(obj))
    if missing:
        raise KeyError(f"missing {name} field:{missing[0]}")
    extra = sorted(set(obj) - allowed)
    if extra:
        raise ValueError(f"unknown {name} field:{extra[0]}")


def _string_array(value: Any, name: str, *, contracts: bool = False) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise ValueError(f"{name} must contain non-empty strings")
    if len(value) != len(set(value)):
        raise ValueError(f"{name} contains duplicates")
    if contracts and any(_CONTRACT_ID_RE.fullmatch(item) is None for item in value):
        raise ValueError("capability_contracts must contain content-addressed contract IDs")
    return value


def validate_policy(policy: dict[str, Any]) -> None:
    """Validate either a root authority policy or a delegated child policy."""
    if not isinstance(policy, dict):
        raise TypeError("policy must be an object")
    validate_canonical(policy)

    has_parent_id = "parent_policy_id" in policy
    has_parent_hash = "parent_policy_hash" in policy
    if has_parent_id != has_parent_hash:
        raise ValueError("child policy parent binding must contain both ID and hash")
    if has_parent_id:
        _require_shape(policy, _CHILD_POLICY_REQUIRED, _CHILD_POLICY_ALLOWED, "child policy")
        if not isinstance(policy["parent_policy_id"], str) or not policy["parent_policy_id"]:
            raise ValueError("invalid child policy field:parent_policy_id")
        if not isinstance(policy["parent_policy_hash"], str) or _HASH_RE.fullmatch(policy["parent_policy_hash"]) is None:
            raise ValueError("invalid child policy field:parent_policy_hash")
    else:
        _require_shape(policy, _POLICY_REQUIRED, _PARENT_POLICY_ALLOWED, "policy")

    for field in ("policy_id", "principal", "expires_at"):
        if not isinstance(policy[field], str) or not policy[field]:
            raise ValueError(f"invalid policy field:{field}")
    for field in ("objectives", "operations", "targets", "destinations", "credentials"):
        _string_array(policy.get(field, []), field)
    _string_array(policy.get("capability_contracts", []), "capability_contracts", contracts=True)

    if policy["max_side_effect"] not in SIDE_EFFECT:
        raise KeyError("unknown max_side_effect")
    budgets = policy["budgets"]
    if not isinstance(budgets, dict) or set(budgets) != _BUDGET_KEYS:
        raise ValueError("budgets must contain exactly the four budget fields")
    for field, value in budgets.items():
        if not isinstance(value, int) or isinstance(value, bool) or value < 0 or value > MAX_SAFE_INTEGER:
            raise ValueError(f"invalid budget:{field}")
    depth = policy.get("max_delegation_depth", 0)
    if not isinstance(depth, int) or isinstance(depth, bool) or depth < 0 or depth > MAX_SAFE_INTEGER:
        raise ValueError("invalid max_delegation_depth")
    if "operator_escalation" in policy and not isinstance(policy["operator_escalation"], bool):
        raise ValueError("operator_escalation must be boolean")
    if has_parent_id and policy.get("operator_escalation", False) is not False:
        raise ValueError("delegated child policy cannot enable operator escalation")
    parse_time(policy["expires_at"])


def validate_action_request(request: dict[str, Any]) -> None:
    """Validate the policy-gate request shape and Canonical JSON value domain."""
    if not isinstance(request, dict):
        raise TypeError("request must be an object")
    validate_canonical(request)
    _require_shape(request, _REQUEST_REQUIRED, _REQUEST_ALLOWED, "request")
    for field in ("request_id", "principal", "objective_id", "operation", "target", "timestamp"):
        if not isinstance(request[field], str) or not request[field]:
            raise ValueError(f"invalid request field:{field}")
    if request["side_effect"] not in SIDE_EFFECT:
        raise KeyError("unknown side_effect")
    for field in ("destination", "credential_ref", "capability_contract_id"):
        value = request.get(field)
        if value is not None and (not isinstance(value, str) or not value):
            raise ValueError(f"invalid request field:{field}")
    contract_id = request.get("capability_contract_id")
    if contract_id is not None and _CONTRACT_ID_RE.fullmatch(contract_id) is None:
        raise ValueError("invalid capability_contract_id")
    usage = request["usage"]
    if not isinstance(usage, dict) or set(usage) != _USAGE_KEYS:
        raise ValueError("usage must contain exactly the four usage fields")
    for field, value in usage.items():
        if not isinstance(value, int) or isinstance(value, bool) or value < 0 or value > MAX_SAFE_INTEGER:
            raise ValueError(f"invalid usage:{field}")
    depth = request.get("delegation_depth", 0)
    if not isinstance(depth, int) or isinstance(depth, bool) or depth < 0 or depth > MAX_SAFE_INTEGER:
        raise ValueError("invalid delegation_depth")
    parse_time(request["timestamp"])


def _outcome(policy: dict[str, Any], hard: bool) -> str:
    if hard:
        return "DENY"
    return "ESCALATE" if policy.get("operator_escalation", False) else "DENY"


def evaluate(policy: dict[str, Any], request: dict[str, Any], now: datetime | None = None) -> dict[str, Any]:
    """Return an auditable decision receipt. Fail closed on malformed input."""
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    else:
        now = now.astimezone(timezone.utc)
    checks: list[tuple[str, bool, bool]] = []

    try:
        validate_policy(policy)
        validate_action_request(request)

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

        allowed_contracts = policy.get("capability_contracts", [])
        contract_id = request.get("capability_contract_id")
        if allowed_contracts:
            checks.append(("capability_contract_scope", contract_id in allowed_contracts, True))
        else:
            checks.append(("capability_contract_scope", contract_id is None, True))

        checks.append(("side_effect_ceiling", SIDE_EFFECT[request["side_effect"]] <= SIDE_EFFECT[policy["max_side_effect"]], True))
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
    except (KeyError, TypeError, ValueError, CanonicalJSONError, RecursionError) as exc:
        reason, decision = f"invalid_request:{type(exc).__name__}", "DENY"

    policy_id = policy.get("policy_id", "UNKNOWN") if isinstance(policy, dict) else "UNKNOWN"
    request_id = request.get("request_id", "UNKNOWN") if isinstance(request, dict) else "UNKNOWN"
    if not isinstance(policy_id, str):
        policy_id = "UNKNOWN"
    if not isinstance(request_id, str):
        request_id = "UNKNOWN"
    return {
        "request_id": request_id,
        "policy_id": policy_id,
        "decision": decision,
        "reason": reason,
        "evaluated_at": now.isoformat().replace("+00:00", "Z"),
        "policy_hash": safe_diagnostic_hash(policy),
        "request_hash": safe_diagnostic_hash(request),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate AMAS AAB action requests")
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--requests", required=True, type=Path)
    args = parser.parse_args()

    policy = json.loads(args.policy.read_text(encoding="utf-8"), parse_constant=lambda value: (_ for _ in ()).throw(ValueError(f"non-finite JSON constant:{value}")))
    requests = json.loads(args.requests.read_text(encoding="utf-8"), parse_constant=lambda value: (_ for _ in ()).throw(ValueError(f"non-finite JSON constant:{value}")))
    if isinstance(requests, dict):
        requests = [requests]

    for request in requests:
        print(json.dumps(evaluate(policy, request), sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
