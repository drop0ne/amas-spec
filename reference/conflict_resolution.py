#!/usr/bin/env python3
"""Deterministic AMAS 2.0-draft conflict arbitration reference.

This module implements the normative ordering in SPEC.md. Semantic role remains
independent from authority tier, and explicit supersession is treated as an
authority-bearing operation rather than trusted because an object names another
object. A trusted caller must verify supersession authority.
"""
from __future__ import annotations

from itertools import combinations
from typing import Any, Callable

from memory_object_validation import (
    DIRECTIVE,
    EVIDENCE,
    INFERENCE,
    OBSERVATION,
    MemoryObjectValidationError,
    parse_time,
    supersession_is_traceable,
    validate_memory_object,
)

SEMANTIC_ROLES = {DIRECTIVE, EVIDENCE, OBSERVATION, INFERENCE}
SupersessionAuthorizer = Callable[[dict[str, Any], dict[str, Any]], bool]


def _scope_relation(a: list[str], b: list[str]) -> int:
    """Return 1 if a is more specific, -1 if b is, otherwise 0."""
    if not isinstance(a, list) or not isinstance(b, list) or not a or not b:
        raise ValueError("scope_path must be a non-empty array")
    if any(not isinstance(part, str) or not part for part in a + b):
        raise ValueError("scope_path elements must be non-empty strings")
    common = min(len(a), len(b))
    if a[:common] != b[:common]:
        return 0
    if len(a) > len(b):
        return 1
    if len(b) > len(a):
        return -1
    return 0


def _validate_object(obj: dict[str, Any]) -> None:
    """Require full Memory Object admission before any authority decision."""
    validate_memory_object(obj)


def directive_admissible(obj: dict[str, Any]) -> bool:
    """Return whether an object may directly authorize behavior."""
    _validate_object(obj)
    return obj["semantic_role"] == DIRECTIVE


def _supersession_authorized(
    candidate: dict[str, Any],
    superseded: dict[str, Any],
    authorizer: SupersessionAuthorizer | None,
) -> tuple[bool, str]:
    """Fail closed unless traceability and external authorization both pass."""
    if not supersession_is_traceable(candidate, superseded):
        return False, "supersession_traceability_failed"
    if authorizer is None:
        return False, "supersession_authorization_unavailable"
    try:
        decision = authorizer(candidate, superseded)
    except Exception as exc:
        return False, f"supersession_authorizer_failed:{type(exc).__name__}"
    if not isinstance(decision, bool):
        return False, "supersession_authorizer_failed:TypeError"
    if not decision:
        return False, "supersession_not_authorized"
    return True, "authorized"


def resolve_pair(
    object_a: dict[str, Any],
    object_b: dict[str, Any],
    *,
    conflict_kind: str = "directive",
    supersession_authorizer: SupersessionAuthorizer | None = None,
) -> dict[str, Any]:
    """Resolve a conflict without probabilistic or text-semantic guessing.

    `conflict_kind="directive"` first applies semantic-role admissibility. Text
    in EVIDENCE/OBSERVATION/INFERENCE remains data even when it contains command
    language. `conflict_kind="claim"` compares objects as epistemic claims.

    Explicit supersession never resolves from object metadata alone. The caller
    must supply a trusted `supersession_authorizer` that authenticates the actor
    and verifies that the actor held authority over the superseded tier/scope.
    """
    try:
        _validate_object(object_a)
        _validate_object(object_b)
        if object_a["object_id"] == object_b["object_id"]:
            raise ValueError("conflicting objects must have distinct object_id values")
        if conflict_kind not in {"directive", "claim"}:
            raise ValueError("unsupported conflict_kind")

        if conflict_kind == "directive":
            a_directive = object_a["semantic_role"] == DIRECTIVE
            b_directive = object_b["semantic_role"] == DIRECTIVE
            if a_directive != b_directive:
                winner = object_a if a_directive else object_b
                loser = object_b if a_directive else object_a
                return {
                    "decision": "RESOLVED",
                    "rule": "semantic_role_admissibility",
                    "winner": winner["object_id"],
                    "loser": loser["object_id"],
                    "reason": "non-directive content cannot authorize behavior",
                }
            if not a_directive and not b_directive:
                return {
                    "decision": "NO_DIRECTIVE",
                    "rule": "semantic_role_admissibility",
                    "winner": None,
                    "loser": None,
                    "reason": "neither object is a directive",
                }

        # Rule 1 — Tier precedence. Lower numeric tier has greater authority.
        if object_a["authority_tier"] != object_b["authority_tier"]:
            winner = object_a if object_a["authority_tier"] < object_b["authority_tier"] else object_b
            loser = object_b if winner is object_a else object_a
            return {
                "decision": "RESOLVED",
                "rule": "rule_1_tier_precedence",
                "winner": winner["object_id"],
                "loser": loser["object_id"],
                "reason": "higher-authority tier prevails",
            }

        # Rule 2 — Explicit supersession. Self-asserted metadata is never enough.
        a_supersedes_b = object_a.get("supersedes") == object_b["object_id"]
        b_supersedes_a = object_b.get("supersedes") == object_a["object_id"]
        if a_supersedes_b and b_supersedes_a:
            return {
                "decision": "HALT_ESCALATE",
                "rule": "rule_5_unresolved",
                "winner": None,
                "loser": None,
                "reason": "cyclic explicit supersession",
            }
        if a_supersedes_b or b_supersedes_a:
            winner = object_a if a_supersedes_b else object_b
            loser = object_b if winner is object_a else object_a
            authorized, reason = _supersession_authorized(winner, loser, supersession_authorizer)
            if not authorized:
                return {
                    "decision": "HALT_ESCALATE",
                    "rule": "rule_5_unresolved",
                    "winner": None,
                    "loser": None,
                    "reason": reason,
                }
            return {
                "decision": "RESOLVED",
                "rule": "rule_2_explicit_supersession",
                "winner": winner["object_id"],
                "loser": loser["object_id"],
                "reason": "supersession is traceable and externally authorized",
            }

        # Rule 3 — Specificity. Only explicit scope-path containment counts.
        relation = _scope_relation(object_a["scope_path"], object_b["scope_path"])
        if relation:
            winner = object_a if relation > 0 else object_b
            loser = object_b if winner is object_a else object_a
            return {
                "decision": "RESOLVED",
                "rule": "rule_3_scope_specificity",
                "winner": winner["object_id"],
                "loser": loser["object_id"],
                "reason": "strictly narrower explicit scope path prevails",
            }

        # Rule 4 — Recency, only after stronger rules tie.
        created_a = parse_time(object_a["created_at"])
        created_b = parse_time(object_b["created_at"])
        if created_a != created_b:
            winner = object_a if created_a > created_b else object_b
            loser = object_b if winner is object_a else object_a
            return {
                "decision": "RESOLVED",
                "rule": "rule_4_recency",
                "winner": winner["object_id"],
                "loser": loser["object_id"],
                "reason": "newer object prevails after stronger rules tie",
            }

        return {
            "decision": "HALT_ESCALATE",
            "rule": "rule_5_unresolved",
            "winner": None,
            "loser": None,
            "reason": "conflict remains unresolved; operator decision required",
        }
    except (KeyError, TypeError, ValueError, MemoryObjectValidationError) as exc:
        return {
            "decision": "HALT_ESCALATE",
            "rule": "invalid_conflict",
            "winner": None,
            "loser": None,
            "reason": f"invalid_conflict:{type(exc).__name__}:{exc}",
        }


def resolve_set(
    objects: list[dict[str, Any]],
    *,
    conflict_kind: str = "directive",
    supersession_authorizer: SupersessionAuthorizer | None = None,
) -> dict[str, Any]:
    """Resolve a multi-object conflict by unique pairwise domination."""
    try:
        if not isinstance(objects, list) or not objects:
            raise ValueError("objects must be a non-empty array")
        if conflict_kind not in {"directive", "claim"}:
            raise ValueError("unsupported conflict_kind")
        for obj in objects:
            if not isinstance(obj, dict):
                raise ValueError("every candidate must be an object")
            _validate_object(obj)
        ids = [obj["object_id"] for obj in objects]
        if len(ids) != len(set(ids)):
            raise ValueError("object_id values must be unique")

        candidates = objects
        excluded: list[str] = []
        if conflict_kind == "directive":
            candidates = [obj for obj in objects if obj["semantic_role"] == DIRECTIVE]
            excluded = [obj["object_id"] for obj in objects if obj["semantic_role"] != DIRECTIVE]
            if not candidates:
                return {
                    "decision": "NO_DIRECTIVE",
                    "rule": "semantic_role_admissibility",
                    "winner": None,
                    "reason": "no directive candidates",
                    "excluded_non_directives": sorted(excluded),
                    "pairwise": [],
                }
            if len(candidates) == 1:
                return {
                    "decision": "RESOLVED",
                    "rule": "semantic_role_admissibility",
                    "winner": candidates[0]["object_id"],
                    "reason": "only one directive candidate remains",
                    "excluded_non_directives": sorted(excluded),
                    "pairwise": [],
                }

        wins: dict[str, set[str]] = {obj["object_id"]: set() for obj in candidates}
        pairwise: list[dict[str, Any]] = []
        for left, right in combinations(candidates, 2):
            result = resolve_pair(
                left,
                right,
                conflict_kind=conflict_kind,
                supersession_authorizer=supersession_authorizer,
            )
            pairwise.append({
                "object_a": left["object_id"],
                "object_b": right["object_id"],
                "decision": result["decision"],
                "rule": result["rule"],
                "winner": result.get("winner"),
            })
            if result["decision"] == "RESOLVED" and result.get("winner") in wins:
                loser = right["object_id"] if result["winner"] == left["object_id"] else left["object_id"]
                wins[result["winner"]].add(loser)

        required_wins = len(candidates) - 1
        dominators = sorted(candidate for candidate, defeated in wins.items() if len(defeated) == required_wins)
        if len(dominators) == 1:
            return {
                "decision": "RESOLVED",
                "rule": "multi_object_unique_dominator",
                "winner": dominators[0],
                "reason": "one candidate defeats every other candidate under pairwise AMAS arbitration",
                "excluded_non_directives": sorted(excluded),
                "pairwise": pairwise,
            }
        return {
            "decision": "HALT_ESCALATE",
            "rule": "rule_5_unresolved",
            "winner": None,
            "reason": "multi-object conflict has no unique pairwise dominator",
            "excluded_non_directives": sorted(excluded),
            "pairwise": pairwise,
        }
    except (KeyError, TypeError, ValueError, MemoryObjectValidationError) as exc:
        return {
            "decision": "HALT_ESCALATE",
            "rule": "invalid_conflict",
            "winner": None,
            "reason": f"invalid_conflict:{type(exc).__name__}:{exc}",
            "excluded_non_directives": [],
            "pairwise": [],
        }
