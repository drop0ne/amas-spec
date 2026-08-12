#!/usr/bin/env python3
"""AMAS AAB monotonic delegation verifier.

Child authority must be a subset of parent authority. This module validates
that a proposed child policy cannot widen objectives, operations, targets,
destinations, credentials, side effects, budgets, expiry, or delegation depth.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

SIDE_EFFECT = {
    "observe": 0,
    "simulate": 1,
    "reversible_write": 2,
    "persistent_write": 3,
    "privileged_change": 4,
}

BUDGET_FIELDS = (
    "max_actions",
    "max_network_calls",
    "max_egress_bytes",
    "max_wall_clock_seconds",
)

SET_FIELDS = (
    "objectives",
    "operations",
    "targets",
    "destinations",
    "credentials",
)


def parse_time(value: str) -> datetime:
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        raise ValueError("timestamps must include timezone")
    return dt.astimezone(timezone.utc)


def _subset(child: list[str], parent: list[str]) -> bool:
    return set(child).issubset(set(parent))


def verify_child_policy(parent: dict[str, Any], child: dict[str, Any]) -> dict[str, Any]:
    """Verify monotonic authority narrowing. Fail closed on malformed input."""
    checks: list[tuple[str, bool]] = []
    try:
        checks.append(("parent_binding", child["parent_policy_id"] == parent["policy_id"]))
        checks.append(("principal_change_explicit", bool(child["principal"])))

        for field in SET_FIELDS:
            checks.append((f"subset:{field}", _subset(child.get(field, []), parent.get(field, []))))

        checks.append((
            "side_effect_narrowing",
            SIDE_EFFECT[child["max_side_effect"]] <= SIDE_EFFECT[parent["max_side_effect"]],
        ))

        parent_budgets = parent["budgets"]
        child_budgets = child["budgets"]
        for field in BUDGET_FIELDS:
            checks.append((f"budget:{field}", child_budgets[field] <= parent_budgets[field]))

        checks.append(("expiry_narrowing", parse_time(child["expires_at"]) <= parse_time(parent["expires_at"])))

        parent_depth = int(parent.get("max_delegation_depth", 0))
        child_depth = int(child.get("max_delegation_depth", 0))
        checks.append(("delegation_depth_remaining", parent_depth > 0 and child_depth <= parent_depth - 1))

        if parent_depth <= 0:
            checks.append(("parent_may_delegate", False))

        failed = [name for name, ok in checks if not ok]
        return {
            "valid": not failed,
            "reason": "authorized_subset" if not failed else failed[0],
            "failed_checks": failed,
            "checks": {name: ok for name, ok in checks},
        }
    except (KeyError, TypeError, ValueError) as exc:
        return {
            "valid": False,
            "reason": f"invalid_policy:{type(exc).__name__}",
            "failed_checks": ["malformed_policy"],
            "checks": {},
        }


def derive_child_policy(parent: dict[str, Any], *, policy_id: str, principal: str, **overrides: Any) -> dict[str, Any]:
    """Create a child candidate by narrowing a parent, then verify it.

    Raises ValueError if the requested child widens authority.
    """
    child = {
        "policy_id": policy_id,
        "parent_policy_id": parent["policy_id"],
        "principal": principal,
        "objectives": list(parent.get("objectives", [])),
        "operations": list(parent.get("operations", [])),
        "targets": list(parent.get("targets", [])),
        "destinations": list(parent.get("destinations", [])),
        "credentials": list(parent.get("credentials", [])),
        "max_side_effect": parent["max_side_effect"],
        "budgets": dict(parent["budgets"]),
        "max_delegation_depth": max(int(parent.get("max_delegation_depth", 0)) - 1, 0),
        "expires_at": parent["expires_at"],
        "operator_escalation": False,
    }
    for key, value in overrides.items():
        if key == "budgets":
            child["budgets"] = {**child["budgets"], **value}
        else:
            child[key] = value

    result = verify_child_policy(parent, child)
    if not result["valid"]:
        raise ValueError(f"child policy widens authority: {result['reason']}")
    return child
