#!/usr/bin/env python3
"""Deterministic AMAS 2.0-draft conflict arbitration reference.

This module implements the normative ordering in SPEC.md. It deliberately keeps
semantic role separate from authority tier: evidence, observations, and
inferences may inform reasoning but cannot become executable directives merely
because their text contains imperative language.
"""
from __future__ import annotations

from datetime import datetime, timezone
from itertools import combinations
from typing import Any

DIRECTIVE = "DIRECTIVE"
EVIDENCE = "EVIDENCE"
OBSERVATION = "OBSERVATION"
INFERENCE = "INFERENCE"
SEMANTIC_ROLES = {DIRECTIVE, EVIDENCE, OBSERVATION, INFERENCE}


def parse_time(value: str) -> datetime:
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        raise ValueError("timestamps must include timezone")
    return dt.astimezone(timezone.utc)


def _scope_relation(a: list[str], b: list[str]) -> int:
    """Return 1 if a is more specific, -1 if b is, otherwise 0.

    Scope specificity is defined only by strict prefix containment. Incomparable
    scope paths are not guessed at and therefore do not resolve Rule 3.
    """
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
    required = {
        "object_id",
        "authority_tier",
        "semantic_role",
        "created_at",
        "scope_path",
    }
    missing = required - set(obj)
    if missing:
        raise ValueError(f"missing fields:{','.join(sorted(missing))}")
    if not isinstance(obj["object_id"], str) or not obj["object_id"]:
        raise ValueError("invalid object_id")
    tier = obj["authority_tier"]
    if not isinstance(tier, int) or isinstance(tier, bool) or tier not in range(4):
        raise ValueError("invalid authority_tier")
    role = obj["semantic_role"]
    if role not in SEMANTIC_ROLES:
        raise ValueError("invalid semantic_role")
    if tier == 3 and role != INFERENCE:
        raise ValueError("Tier 3 objects must be INFERENCE")
    if role == INFERENCE and tier != 3:
        raise ValueError("INFERENCE objects must be Tier 3")
    parse_time(obj["created_at"])
    _scope_relation(obj["scope_path"], obj["scope_path"])


def directive_admissible(obj: dict[str, Any]) -> bool:
    """Return whether an object may directly authorize behavior."""
    _validate_object(obj)
    return obj["semantic_role"] == DIRECTIVE


def resolve_pair(
    object_a: dict[str, Any],
    object_b: dict[str, Any],
    *,
    conflict_kind: str = "directive",
) -> dict[str, Any]:
    """Resolve a conflict without probabilistic or text-semantic guessing.

    `conflict_kind="directive"` first applies semantic-role admissibility. Text
    in EVIDENCE/OBSERVATION/INFERENCE is data even if it contains commands.
    `conflict_kind="claim"` compares the objects as epistemic claims.
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

        # Rule 2 — Explicit supersession. Contradictory/cyclic supersession is
        # not guessed through; it fails closed to operator resolution.
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
            return {
                "decision": "RESOLVED",
                "rule": "rule_2_explicit_supersession",
                "winner": winner["object_id"],
                "loser": loser["object_id"],
                "reason": "authorized supersession relationship is explicit",
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

        # Rule 4 — Recency. Timestamps are compared only after tier,
        # supersession, and explicit scope specificity fail to resolve.
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

        # Rule 5 — Unique conservative default. There is deliberately no
        # implementation-selected "more restrictive" fallback because that
        # would reintroduce ambiguity into a deterministic protocol.
        return {
            "decision": "HALT_ESCALATE",
            "rule": "rule_5_unresolved",
            "winner": None,
            "loser": None,
            "reason": "conflict remains unresolved; operator decision required",
        }
    except (KeyError, TypeError, ValueError) as exc:
        return {
            "decision": "HALT_ESCALATE",
            "rule": "invalid_conflict",
            "winner": None,
            "loser": None,
            "reason": f"invalid_conflict:{type(exc).__name__}:{exc}",
        }


def resolve_set(objects: list[dict[str, Any]], *, conflict_kind: str = "directive") -> dict[str, Any]:
    """Resolve a multi-object conflict by unique pairwise domination.

    A candidate is a winner only if it defeats every other candidate under the
    exact pairwise protocol. This intentionally conservative rule is independent
    of input order and avoids inventing transitive precedence where pairwise
    arbitration left a relation unresolved. If no unique all-dominator exists,
    Rule 5 applies.
    """
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
            result = resolve_pair(left, right, conflict_kind=conflict_kind)
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
    except (KeyError, TypeError, ValueError) as exc:
        return {
            "decision": "HALT_ESCALATE",
            "rule": "invalid_conflict",
            "winner": None,
            "reason": f"invalid_conflict:{type(exc).__name__}:{exc}",
            "excluded_non_directives": [],
            "pairwise": [],
        }
