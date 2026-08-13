#!/usr/bin/env python3
"""AMAS AAB reference enforcement broker.

Security-critical mutable state lives outside the acting model. HMAC-SHA256 is
retained only as a compact reference authentication mechanism. Lease admission
uses the same exact policy validator as the policy gate/delegation runtime so a
cryptographically authentic but schema-invalid envelope cannot enter broker
state.
"""
from __future__ import annotations

import copy
import hashlib
import hmac
import re
from datetime import datetime, timezone
from typing import Any, Callable

from authority_gate import evaluate, parse_time, safe_diagnostic_hash, validate_policy
from canonical_json import CanonicalJSONError, MAX_SAFE_INTEGER, bytes_ as canonical_bytes, sha256 as canonical_hash, validate as validate_canonical
from receipt_chain import GENESIS, append_receipt, verify_chain

USAGE_KEYS = ("actions", "network_calls", "egress_bytes", "wall_clock_seconds")
_MIN_NONCE_LENGTH = 16
_LEASE_REQUIRED = {
    "lease_version",
    "lease_id",
    "issuer",
    "key_id",
    "issued_at",
    "not_before",
    "max_request_age_seconds",
    "signature_alg",
    "policy",
    "signature",
}
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


def _canonical_bytes(obj: Any) -> bytes:
    return canonical_bytes(obj)


def _hash(obj: Any) -> str:
    return canonical_hash(obj)


def _validate_key(key: bytes) -> bytes:
    if not isinstance(key, bytes) or not key:
        raise ValueError("reference HMAC key must be non-empty bytes")
    return key


def _unsigned_lease(lease: dict[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(lease)
    out.pop("signature", None)
    return out


def sign_lease(lease: dict[str, Any], key: bytes) -> str:
    """Return HMAC-SHA256 over Canonical JSON v1 lease bytes."""
    _validate_key(key)
    if not isinstance(lease, dict):
        raise ValueError("lease must be an object")
    return hmac.new(key, _canonical_bytes(_unsigned_lease(lease)), hashlib.sha256).hexdigest()


def verify_lease_signature(lease: dict[str, Any], key: bytes) -> bool:
    try:
        _validate_key(key)
        if not isinstance(lease, dict):
            return False
        signature = lease.get("signature")
        if not isinstance(signature, str) or _HEX64_RE.fullmatch(signature) is None:
            return False
        return hmac.compare_digest(signature, sign_lease(lease, key))
    except (TypeError, ValueError, CanonicalJSONError, RecursionError):
        return False


def _validate_lease_shape(lease: dict[str, Any]) -> tuple[datetime, datetime]:
    if not isinstance(lease, dict) or set(lease) != _LEASE_REQUIRED:
        raise ValueError("lease must contain exactly the signed lease schema fields")
    validate_canonical(lease)
    if lease.get("signature_alg") != "HMAC-SHA256":
        raise ValueError("unsupported signature algorithm")
    if lease.get("lease_version") != 1:
        raise ValueError("unsupported lease version")
    for field in ("lease_id", "issuer", "key_id"):
        if not isinstance(lease.get(field), str) or not lease[field]:
            raise ValueError(f"invalid {field}")
    signature = lease.get("signature")
    if not isinstance(signature, str) or _HEX64_RE.fullmatch(signature) is None:
        raise ValueError("invalid signature")
    issued = parse_time(lease["issued_at"])
    not_before = parse_time(lease["not_before"])
    if not_before < issued:
        raise ValueError("not_before cannot precede issued_at")
    max_age = lease.get("max_request_age_seconds")
    if not isinstance(max_age, int) or isinstance(max_age, bool) or max_age < 0 or max_age > MAX_SAFE_INTEGER:
        raise ValueError("invalid max_request_age_seconds")
    validate_policy(lease["policy"])
    if parse_time(lease["policy"]["expires_at"]) < not_before:
        raise ValueError("policy expires before lease becomes valid")
    return issued, not_before


def _zero_usage() -> dict[str, int]:
    return {name: 0 for name in USAGE_KEYS}


def _validate_cost(cost: Any) -> dict[str, int]:
    if not isinstance(cost, dict) or set(cost) != set(USAGE_KEYS):
        raise ValueError("cost must contain exactly the four broker usage fields")
    normalized: dict[str, int] = {}
    for name in USAGE_KEYS:
        value = cost[name]
        if not isinstance(value, int) or isinstance(value, bool) or value < 0 or value > MAX_SAFE_INTEGER:
            raise ValueError(f"invalid non-negative canonical integer cost: {name}")
        normalized[name] = value
    if normalized["actions"] < 1:
        raise ValueError("every evaluated side-effect request must cost at least one action")
    return normalized


def _validate_execution_binding(value: str | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or _HEX64_RE.fullmatch(value) is None:
        raise ValueError("execution binding must be a lowercase SHA-256 hex string")
    return value


class RevocationRegistry:
    """Minimal mutable reference revocation registry."""

    def __init__(self, revoked: set[str] | None = None):
        self._revoked = set(revoked or set())

    def revoke(self, lease_id: str) -> None:
        if not isinstance(lease_id, str) or not lease_id:
            raise ValueError("invalid lease_id")
        self._revoked.add(lease_id)

    def is_revoked(self, lease_id: str) -> bool:
        return lease_id in self._revoked


class EnforcementBroker:
    """Stateful AAB authorization boundary."""

    def __init__(
        self,
        lease: dict[str, Any],
        verification_key: bytes,
        *,
        revocation_checker: Callable[[str], bool] | None = None,
    ):
        _validate_key(verification_key)
        if not isinstance(lease, dict):
            raise ValueError("lease must be an object")
        _, not_before = _validate_lease_shape(lease)
        if not verify_lease_signature(lease, verification_key):
            raise ValueError("invalid lease signature")
        if revocation_checker is not None and not callable(revocation_checker):
            raise ValueError("revocation_checker must be callable")

        self.lease = copy.deepcopy(lease)
        self.policy = copy.deepcopy(lease["policy"])
        self.not_before = not_before
        self.revocation_checker = revocation_checker
        self.usage = _zero_usage()
        self.seen_nonces: set[str] = set()
        self.last_sequence = 0
        self.receipts: list[dict[str, Any]] = []

    def _chain(self, receipt: dict[str, Any]) -> dict[str, Any]:
        previous = self.receipts[-1]["receipt_hash"] if self.receipts else GENESIS
        chained = append_receipt(receipt, previous_hash=previous, sequence=len(self.receipts))
        self.receipts.append(chained)
        return chained

    def _reject(
        self,
        request: Any,
        reason: str,
        now: datetime,
        *,
        execution_binding_hash: str | None = None,
        raw_request_hash: str | None = None,
    ) -> dict[str, Any]:
        request_dict = request if isinstance(request, dict) else {}
        request_id = request_dict.get("request_id", "UNKNOWN")
        if not isinstance(request_id, str):
            request_id = "UNKNOWN"
        policy_id = self.policy.get("policy_id", "UNKNOWN")
        if not isinstance(policy_id, str):
            policy_id = "UNKNOWN"
        receipt = {
            "request_id": request_id,
            "policy_id": policy_id,
            "decision": "DENY",
            "reason": reason,
            "evaluated_at": now.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
            "policy_hash": safe_diagnostic_hash(self.policy),
            "request_hash": raw_request_hash or safe_diagnostic_hash(request),
            "lease_id": self.lease["lease_id"],
            "authoritative_usage": dict(self.usage),
        }
        if execution_binding_hash is not None:
            receipt["execution_binding_hash"] = execution_binding_hash
        return self._chain(receipt)

    def _revocation_status(self) -> tuple[bool, str | None]:
        if self.revocation_checker is None:
            return False, None
        try:
            result = self.revocation_checker(self.lease["lease_id"])
        except Exception as exc:
            return True, f"revocation_check_failed:{type(exc).__name__}"
        if not isinstance(result, bool):
            return True, "revocation_check_failed:TypeError"
        return result, "lease_revoked" if result else None

    def authorize(
        self,
        request: dict[str, Any],
        *,
        cost: dict[str, int],
        now: datetime | None = None,
        execution_binding_hash: str | None = None,
    ) -> dict[str, Any]:
        now = now or datetime.now(timezone.utc)
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
        else:
            now = now.astimezone(timezone.utc)
        if not isinstance(request, dict):
            return self._reject(request, "invalid_envelope:TypeError", now)

        raw_request_hash: str | None = None
        binding: str | None = None
        try:
            validate_canonical(request)
            raw_request_hash = _hash(request)
            binding = _validate_execution_binding(execution_binding_hash)

            revoked, revocation_reason = self._revocation_status()
            if revoked:
                return self._reject(request, revocation_reason or "lease_revoked", now, execution_binding_hash=binding, raw_request_hash=raw_request_hash)
            if now < self.not_before:
                return self._reject(request, "lease_not_yet_valid", now, execution_binding_hash=binding, raw_request_hash=raw_request_hash)
            if request["lease_id"] != self.lease["lease_id"]:
                return self._reject(request, "lease_binding", now, execution_binding_hash=binding, raw_request_hash=raw_request_hash)

            nonce = request["nonce"]
            if not isinstance(nonce, str) or len(nonce) < _MIN_NONCE_LENGTH:
                return self._reject(request, "invalid_nonce", now, execution_binding_hash=binding, raw_request_hash=raw_request_hash)
            if nonce in self.seen_nonces:
                return self._reject(request, "replay_nonce", now, execution_binding_hash=binding, raw_request_hash=raw_request_hash)

            sequence = request["sequence"]
            if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1 or sequence > MAX_SAFE_INTEGER:
                return self._reject(request, "invalid_sequence", now, execution_binding_hash=binding, raw_request_hash=raw_request_hash)
            if sequence != self.last_sequence + 1:
                return self._reject(request, "sequence_violation", now, execution_binding_hash=binding, raw_request_hash=raw_request_hash)

            request_time = parse_time(request["timestamp"])
            age_seconds = (now - request_time).total_seconds()
            if age_seconds < -30:
                return self._reject(request, "request_from_future", now, execution_binding_hash=binding, raw_request_hash=raw_request_hash)
            if age_seconds > self.lease["max_request_age_seconds"]:
                return self._reject(request, "stale_request", now, execution_binding_hash=binding, raw_request_hash=raw_request_hash)

            delta = _validate_cost(cost)
            prospective: dict[str, int] = {}
            for name in USAGE_KEYS:
                value = self.usage[name] + delta[name]
                if value > MAX_SAFE_INTEGER:
                    return self._reject(request, "usage_counter_overflow", now, execution_binding_hash=binding, raw_request_hash=raw_request_hash)
                prospective[name] = value

            gate_request = copy.deepcopy(request)
            gate_request.pop("lease_id", None)
            gate_request.pop("nonce", None)
            gate_request.pop("sequence", None)
            gate_request.pop("usage", None)
            gate_request["usage"] = dict(prospective)

            receipt = evaluate(self.policy, gate_request, now)
            receipt["policy_request_hash"] = receipt.pop("request_hash")
            receipt["request_hash"] = raw_request_hash
            receipt["lease_id"] = self.lease["lease_id"]
            receipt["authoritative_usage"] = dict(prospective)
            if binding is not None:
                receipt["execution_binding_hash"] = binding

            self.seen_nonces.add(nonce)
            self.last_sequence = sequence
            if receipt["decision"] == "ALLOW":
                self.usage = dict(prospective)
            else:
                attempted_actions = self.usage["actions"] + delta["actions"]
                if attempted_actions > MAX_SAFE_INTEGER:
                    return self._reject(request, "usage_counter_overflow", now, execution_binding_hash=binding, raw_request_hash=raw_request_hash)
                self.usage["actions"] = attempted_actions
                receipt["authoritative_usage"] = dict(self.usage)
            return self._chain(receipt)

        except (KeyError, TypeError, ValueError, CanonicalJSONError, RecursionError) as exc:
            return self._reject(
                request,
                f"invalid_envelope:{type(exc).__name__}",
                now,
                execution_binding_hash=binding,
                raw_request_hash=raw_request_hash,
            )

    def verify_receipts(self) -> bool:
        return bool(verify_chain(self.receipts)["valid"])

    def receipt_verification(self) -> dict[str, Any]:
        return verify_chain(self.receipts)

    def snapshot(self) -> dict[str, Any]:
        verification = self.receipt_verification()
        return {
            "lease_id": self.lease["lease_id"],
            "policy_id": self.policy.get("policy_id"),
            "last_sequence": self.last_sequence,
            "usage": dict(self.usage),
            "seen_nonce_count": len(self.seen_nonces),
            "receipt_count": len(self.receipts),
            "receipt_chain_valid": verification["valid"],
            "receipt_chain_tip": verification.get("chain_tip"),
            "receipt_chain_error": None if verification["valid"] else verification.get("reason"),
        }
