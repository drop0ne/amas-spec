#!/usr/bin/env python3
"""Strict AMAS 2.0-draft Memory Object admission checks.

The JSON Schema remains the normative machine-readable structural contract.
This module mirrors the security-relevant schema rules with standard-library
checks so authority arbitration never operates on malformed Memory Objects.

Authentication is deliberately not inferred from self-asserted metadata.
`authn_context` and provenance make an authority-bearing transition traceable;
a trusted caller/verifier must separately establish that the asserted actor was
actually authorized for the transition.
"""
from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any

DIRECTIVE = "DIRECTIVE"
EVIDENCE = "EVIDENCE"
OBSERVATION = "OBSERVATION"
INFERENCE = "INFERENCE"
SEMANTIC_ROLES = {DIRECTIVE, EVIDENCE, OBSERVATION, INFERENCE}

_REQUIRED_FIELDS = {
    "object_id",
    "authority_tier",
    "semantic_role",
    "content",
    "source_id",
    "created_at",
    "scope",
    "scope_path",
    "mutable",
    "inference_marker",
}
_OPTIONAL_FIELDS = {
    "confidence",
    "expires_at",
    "escalated_from",
    "escalated_by",
    "supersedes",
    "provenance",
    "authn_context",
}
_ALLOWED_FIELDS = _REQUIRED_FIELDS | _OPTIONAL_FIELDS


class MemoryObjectValidationError(ValueError):
    pass


def parse_time(value: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise MemoryObjectValidationError("timestamp must be a non-empty string")
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(value)
    except ValueError as exc:
        raise MemoryObjectValidationError("invalid date-time") from exc
    if dt.tzinfo is None:
        raise MemoryObjectValidationError("timestamps must include timezone")
    return dt.astimezone(timezone.utc)


def _nonempty_string(value: Any, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise MemoryObjectValidationError(f"{name} must be a non-empty string")
    return value


def _validate_provenance(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {"origin", "chain"}:
        raise MemoryObjectValidationError("provenance must contain exactly origin and chain")
    _nonempty_string(value["origin"], "provenance.origin")
    chain = value["chain"]
    if not isinstance(chain, list) or any(not isinstance(item, str) or not item for item in chain):
        raise MemoryObjectValidationError("provenance.chain must be an array of non-empty strings")
    if len(chain) != len(set(chain)):
        raise MemoryObjectValidationError("provenance.chain must not contain duplicates")
    return value


def validate_memory_object(obj: dict[str, Any]) -> None:
    """Raise unless *obj* satisfies the runtime Memory Object contract."""
    if not isinstance(obj, dict):
        raise MemoryObjectValidationError("Memory Object must be an object")
    missing = sorted(_REQUIRED_FIELDS - set(obj))
    if missing:
        raise MemoryObjectValidationError(f"missing field:{missing[0]}")
    extra = sorted(set(obj) - _ALLOWED_FIELDS)
    if extra:
        raise MemoryObjectValidationError(f"unknown field:{extra[0]}")

    _nonempty_string(obj["object_id"], "object_id")
    if not isinstance(obj["content"], str):
        raise MemoryObjectValidationError("content must be a string")
    _nonempty_string(obj["source_id"], "source_id")
    _nonempty_string(obj["scope"], "scope")

    tier = obj["authority_tier"]
    if not isinstance(tier, int) or isinstance(tier, bool) or tier not in range(4):
        raise MemoryObjectValidationError("authority_tier must be an integer from 0 through 3")
    role = obj["semantic_role"]
    if role not in SEMANTIC_ROLES:
        raise MemoryObjectValidationError("invalid semantic_role")

    parse_time(obj["created_at"])
    scope_path = obj["scope_path"]
    if not isinstance(scope_path, list) or not 1 <= len(scope_path) <= 32:
        raise MemoryObjectValidationError("scope_path must contain 1 through 32 elements")
    if any(not isinstance(part, str) or not part for part in scope_path):
        raise MemoryObjectValidationError("scope_path elements must be non-empty strings")

    if not isinstance(obj["mutable"], bool):
        raise MemoryObjectValidationError("mutable must be boolean")
    if not isinstance(obj["inference_marker"], bool):
        raise MemoryObjectValidationError("inference_marker must be boolean")

    if tier == 3 and (role != INFERENCE or obj["inference_marker"] is not True):
        raise MemoryObjectValidationError("Tier 3 must be marked INFERENCE")
    if role == INFERENCE and (tier != 3 or obj["inference_marker"] is not True):
        raise MemoryObjectValidationError("INFERENCE must be Tier 3 with inference_marker true")
    if role == DIRECTIVE and tier > 2:
        raise MemoryObjectValidationError("DIRECTIVE cannot be Tier 3")
    if tier == 0 and obj["mutable"] is not False:
        raise MemoryObjectValidationError("Tier 0 must be immutable")

    confidence = obj.get("confidence")
    if confidence is not None:
        if not isinstance(confidence, (int, float)) or isinstance(confidence, bool):
            raise MemoryObjectValidationError("confidence must be a number or null")
        if not math.isfinite(confidence) or not 0 <= confidence <= 1:
            raise MemoryObjectValidationError("confidence must be finite and within [0,1]")

    expires_at = obj.get("expires_at")
    if expires_at is not None:
        parse_time(expires_at)

    escalated_from = obj.get("escalated_from")
    if escalated_from is not None:
        if not isinstance(escalated_from, int) or isinstance(escalated_from, bool) or escalated_from not in range(4):
            raise MemoryObjectValidationError("escalated_from must be an integer from 0 through 3 or null")
    escalated_by = obj.get("escalated_by")
    if escalated_by is not None:
        _nonempty_string(escalated_by, "escalated_by")
    authn_context = obj.get("authn_context")
    if authn_context is not None:
        _nonempty_string(authn_context, "authn_context")
    provenance = _validate_provenance(obj.get("provenance"))

    # Escalation is a distinct authority-bearing transition. A generic
    # authn_context may also support supersession, so authn_context by itself is
    # not treated as proof that escalation occurred.
    escalation_present = escalated_from is not None or escalated_by is not None
    if escalation_present:
        if escalated_from is None or escalated_by is None or authn_context is None or provenance is None:
            raise MemoryObjectValidationError("escalation metadata must be complete and provenance-bound")
        if tier >= escalated_from:
            raise MemoryObjectValidationError("escalation target must be a strictly higher authority tier")

    supersedes = obj.get("supersedes")
    if supersedes is not None:
        _nonempty_string(supersedes, "supersedes")
        if supersedes == obj["object_id"]:
            raise MemoryObjectValidationError("Memory Object cannot supersede itself")
        if authn_context is None or provenance is None:
            raise MemoryObjectValidationError("supersession requires authenticated provenance")


def supersession_is_traceable(candidate: dict[str, Any], superseded: dict[str, Any]) -> bool:
    """Check structural traceability of a same-tier supersession claim.

    This check is necessary but not sufficient authorization. The conflict
    resolver additionally requires a trusted supersession authorizer callback.
    """
    try:
        validate_memory_object(candidate)
        validate_memory_object(superseded)
        if candidate.get("supersedes") != superseded["object_id"]:
            return False
        if candidate["authority_tier"] != superseded["authority_tier"]:
            return False
        authn_context = candidate.get("authn_context")
        provenance = candidate.get("provenance")
        if not isinstance(authn_context, str) or not authn_context:
            return False
        if not isinstance(provenance, dict) or provenance.get("origin") != candidate.get("source_id"):
            return False
        chain = provenance.get("chain")
        if not isinstance(chain, list) or len(chain) < 2:
            return False
        # The provenance must describe a forward transition from the exact
        # superseded object to the candidate, not merely mention both IDs.
        return (
            chain[0] == superseded["object_id"]
            and chain[-1] == candidate["object_id"]
            and len(chain) == len(set(chain))
        )
    except (MemoryObjectValidationError, KeyError, TypeError, ValueError):
        return False
