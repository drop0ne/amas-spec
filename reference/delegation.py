#!/usr/bin/env python3
"""AMAS AAB monotonic delegation verifier.

Child authority must be a subset of parent authority across every security-
relevant dimension. Parent and child objects are admitted through the same
policy validator used by the authorization gate so `authorized_subset` can never
certify a schema-shaped-invalid policy.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from authority_gate import SIDE_EFFECT, validate_policy
from canonical_json import CanonicalJSONError, MAX_SAFE_INTEGER, sha256 as canonical_sha256, validate as validate_canonical

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
    "capability_contracts",
)

_CHILD_FIELDS = {
    "policy_id", "parent_policy_id", "parent_policy_hash", "principal",
    "objectives", "operations", "targets", "destinations", "credentials",
    "capability_contracts", "max_side_effect", "budgets", "max_delegation_depth",
    "expires_at", "operator_escalation",
}


def canonical_policy_hash(policy: dict[str, Any]) -> str:
    if not isinstance(policy, dict):
        raise ValueError("policy must be an object")
    try:
        validate_canonical(policy)
        return canonical_sha256(policy)
    except CanonicalJSONError as exc:
        raise ValueError("policy does not satisfy Canonical JSON v1") from exc


def parse_time(value: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise ValueError("timestamp must be a non-empty string")
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        raise ValueError("timestamps must include timezone")
    return dt.astimezone(timezone.utc)


def _string_set(value: Any, name: str) -> set[str]:
    if not isinstance(value, list):
        raise ValueError(f"{name} must be an array")
    if any(not isinstance(item, str) or not item for item in value):
        raise ValueError(f"{name} must contain non-empty strings")
    if len(value) != len(set(value)):
        raise ValueError(f"{name} contains duplicates")
    return set(value)


def _budget_map(policy: dict[str, Any]) -> dict[str, int]:
    budgets = policy["budgets"]
    if not isinstance(budgets, dict) or set(budgets) != set(BUDGET_FIELDS):
        raise ValueError("budgets must contain exactly the four authority budget fields")
    out: dict[str, int] = {}
    for field in BUDGET_FIELDS:
        value = budgets[field]
        if not isinstance(value, int) or isinstance(value, bool) or value < 0 or value > MAX_SAFE_INTEGER:
            raise ValueError(f"invalid budget:{field}")
        out[field] = value
    return out


def verify_child_policy(parent: dict[str, Any], child: dict[str, Any]) -> dict[str, Any]:
    """Verify monotonic authority narrowing. Fail closed on malformed input."""
    checks: list[tuple[str, bool]] = []
    try:
        if not isinstance(parent, dict) or not isinstance(child, dict):
            raise ValueError("parent and child must be objects")
        # A delegation parent is a root policy; a child must carry exact parent
        # bindings. The shared validator also rejects unknown fields.
        validate_policy(parent)
        if "parent_policy_id" in parent or "parent_policy_hash" in parent:
            raise ValueError("delegation parent must be a root authority policy")
        validate_policy(child)
        if set(child) - _CHILD_FIELDS:
            raise ValueError("unknown child policy field")
        if "parent_policy_id" not in child or "parent_policy_hash" not in child:
            raise ValueError("child policy is missing parent binding")
        parent_hash = canonical_policy_hash(parent)

        if child["policy_id"] == parent["policy_id"]:
            raise ValueError("child policy_id must differ from parent")

        checks.append(("parent_id_binding", child["parent_policy_id"] == parent["policy_id"]))
        checks.append(("parent_hash_binding", child["parent_policy_hash"] == parent_hash))

        for field in SET_FIELDS:
            parent_values = _string_set(parent.get(field, []), f"parent.{field}")
            child_values = _string_set(child.get(field, []), f"child.{field}")
            checks.append((f"subset:{field}", child_values.issubset(parent_values)))

        checks.append((
            "side_effect_narrowing",
            SIDE_EFFECT[child["max_side_effect"]] <= SIDE_EFFECT[parent["max_side_effect"]],
        ))

        parent_budgets = _budget_map(parent)
        child_budgets = _budget_map(child)
        for field in BUDGET_FIELDS:
            checks.append((f"budget:{field}", child_budgets[field] <= parent_budgets[field]))

        checks.append(("expiry_narrowing", parse_time(child["expires_at"]) <= parse_time(parent["expires_at"])))

        parent_depth = parent.get("max_delegation_depth", 0)
        child_depth = child.get("max_delegation_depth", 0)
        if not isinstance(parent_depth, int) or isinstance(parent_depth, bool) or parent_depth < 0 or parent_depth > MAX_SAFE_INTEGER:
            raise ValueError("invalid parent delegation depth")
        if not isinstance(child_depth, int) or isinstance(child_depth, bool) or child_depth < 0 or child_depth > MAX_SAFE_INTEGER:
            raise ValueError("invalid child delegation depth")
        checks.append(("parent_may_delegate", parent_depth > 0))
        checks.append(("delegation_depth_remaining", parent_depth > 0 and child_depth <= parent_depth - 1))
        checks.append(("no_child_operator_escalation", child.get("operator_escalation", False) is False))

        failed = [name for name, ok in checks if not ok]
        return {
            "valid": not failed,
            "reason": "authorized_subset" if not failed else failed[0],
            "failed_checks": failed,
            "checks": {name: ok for name, ok in checks},
            "parent_policy_hash": parent_hash,
        }
    except (KeyError, TypeError, ValueError, CanonicalJSONError, RecursionError) as exc:
        return {
            "valid": False,
            "reason": f"invalid_policy:{type(exc).__name__}",
            "failed_checks": ["malformed_policy"],
            "checks": {},
            "parent_policy_hash": None,
        }


def derive_child_policy(parent: dict[str, Any], *, policy_id: str, principal: str, **overrides: Any) -> dict[str, Any]:
    """Create a child candidate by narrowing a root parent, then verify it."""
    if not isinstance(policy_id, str) or not policy_id or not isinstance(principal, str) or not principal:
        raise ValueError("policy_id and principal must be non-empty strings")
    validate_policy(parent)
    if "parent_policy_id" in parent or "parent_policy_hash" in parent:
        raise ValueError("derive_child_policy requires a root parent policy")
    parent_hash = canonical_policy_hash(parent)
    child = {
        "policy_id": policy_id,
        "parent_policy_id": parent["policy_id"],
        "parent_policy_hash": parent_hash,
        "principal": principal,
        "objectives": list(parent.get("objectives", [])),
        "operations": list(parent.get("operations", [])),
        "targets": list(parent.get("targets", [])),
        "destinations": list(parent.get("destinations", [])),
        "credentials": list(parent.get("credentials", [])),
        "capability_contracts": list(parent.get("capability_contracts", [])),
        "max_side_effect": parent["max_side_effect"],
        "budgets": dict(parent["budgets"]),
        "max_delegation_depth": max(int(parent.get("max_delegation_depth", 0)) - 1, 0),
        "expires_at": parent["expires_at"],
        "operator_escalation": False,
    }
    protected = {"parent_policy_id", "parent_policy_hash"}
    if protected & set(overrides):
        raise ValueError("parent binding fields are derived and cannot be overridden")
    for key, value in overrides.items():
        if key not in _CHILD_FIELDS:
            raise ValueError(f"unknown child override:{key}")
        if key == "budgets":
            if not isinstance(value, dict):
                raise ValueError("budgets override must be an object")
            child["budgets"] = {**child["budgets"], **value}
        else:
            child[key] = value

    result = verify_child_policy(parent, child)
    if not result["valid"]:
        raise ValueError(f"child policy widens authority: {result['reason']}")
    return child
