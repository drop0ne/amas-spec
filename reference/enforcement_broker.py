#!/usr/bin/env python3
"""AMAS AAB reference enforcement broker.

Security-critical state lives outside the acting model:
- authenticated authority leases
- request freshness, nonce replay protection, and monotonic sequence
- broker-owned cumulative budgets
- optional external lease revocation
- tamper-evident decision receipts
- optional execution-binding hash covered by the receipt chain

The broker authorizes requests; mediated execution is implemented separately.
HMAC-SHA256 is retained only as a compact reference mechanism.
"""
from __future__ import annotations

import copy
import hashlib
import hmac
import json
import re
from datetime import datetime, timezone
from typing import Any, Callable

from authority_gate import evaluate, parse_time
from receipt_chain import GENESIS, append_receipt, verify_chain

USAGE_KEYS = ("actions", "network_calls", "egress_bytes", "wall_clock_seconds")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_MIN_NONCE_LENGTH = 16


def _canonical_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _hash(obj: Any) -> str:
    return hashlib.sha256(_canonical_bytes(obj)).hexdigest()


def _unsigned_lease(lease: dict[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(lease)
    out.pop("signature", None)
    return out


def sign_lease(lease: dict[str, Any], key: bytes) -> str:
    """Return HMAC-SHA256 over the canonical lease excluding `signature`."""
    return hmac.new(key, _canonical_bytes(_unsigned_lease(lease)), hashlib.sha256).hexdigest()


def verify_lease_signature(lease: dict[str, Any], key: bytes) -> bool:
    signature = lease.get("signature")
    if not isinstance(signature, str):
        return False
    expected = sign_lease(lease, key)
    return hmac.compare_digest(signature, expected)


def _zero_usage() -> dict[str, int]:
    return {name: 0 for name in USAGE_KEYS}


def _validate_cost(cost: Any) -> dict[str, int]:
    if not isinstance(cost, dict):
        raise ValueError("cost must be an object")
    if set(cost) != set(USAGE_KEYS):
        raise ValueError("cost must contain exactly the four broker usage fields")
    normalized: dict[str, int] = {}
    for name in USAGE_KEYS:
        value = cost[name]
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError(f"invalid non-negative integer cost: {name}")
        normalized[name] = value
    if normalized["actions"] < 1:
        raise ValueError("every evaluated side-effect request must cost at least one action")
    return normalized


def _validate_execution_binding(value: str | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise ValueError("execution_binding_hash must be a lowercase SHA-256 hex digest")
    return value


class RevocationRegistry:
    """Minimal mutable reference revocation registry.

    Production deployments should use an authenticated, durable registry in a
    failure domain the acting model cannot modify.
    """

    def __init__(self, revoked: set[str] | None = None):
        self._revoked = set(revoked or set())

    def revoke(self, lease_id: str) -> None:
        self._revoked.add(lease_id)

    def is_revoked(self, lease_id: str) -> bool:
        return lease_id in self._revoked


class EnforcementBroker:
    """Stateful AAB authorization boundary.

    `cost` and any execution-binding hash must originate from trusted mediation
    code, not from an agent-controlled claim.
    """

    def __init__(
        self,
        lease: dict[str, Any],
        verification_key: bytes,
        *,
        revocation_checker: Callable[[str], bool] | None = None,
    ):
        if not verify_lease_signature(lease, verification_key):
            raise ValueError("invalid lease signature")
        if lease.get("signature_alg") != "HMAC-SHA256":
            raise ValueError("unsupported signature algorithm")
        if not isinstance(lease.get("lease_id"), str) or not lease["lease_id"]:
            raise ValueError("invalid lease_id")
        if not isinstance(lease.get("issuer"), str) or not lease["issuer"]:
            raise ValueError("invalid issuer")
        issued = parse_time(lease["issued_at"])
        not_before = parse_time(lease.get("not_before", lease["issued_at"]))
        if not_before < issued:
            raise ValueError("not_before cannot precede issued_at")
        if not isinstance(lease.get("max_request_age_seconds"), int) or lease["max_request_age_seconds"] < 0:
            raise ValueError("invalid max_request_age_seconds")
        if not isinstance(lease.get("policy"), dict):
            raise ValueError("missing policy")
        if "lease_version" in lease and lease["lease_version"] != 1:
            raise ValueError("unsupported lease_version")
        if "key_id" in lease and (not isinstance(lease["key_id"], str) or not lease["key_id"]):
            raise ValueError("invalid key_id")
        if parse_time(lease["policy"]["expires_at"]) < not_before:
            raise ValueError("policy expires before lease becomes valid")

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
        request: dict[str, Any],
        reason: str,
        now: datetime,
        *,
        execution_binding_hash: str | None = None,
    ) -> dict[str, Any]:
        receipt = {
            "request_id": request.get("request_id", "UNKNOWN"),
            "policy_id": self.policy.get("policy_id", "UNKNOWN"),
            "decision": "DENY",
            "reason": reason,
            "evaluated_at": now.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
            "policy_hash": _hash(self.policy),
            "request_hash": _hash(request),
            "lease_id": self.lease["lease_id"],
            "authoritative_usage": dict(self.usage),
        }
        if execution_binding_hash is not None:
            receipt["execution_binding_hash"] = execution_binding_hash
        return self._chain(receipt)

    def authorize(
        self,
        request: dict[str, Any],
        *,
        cost: dict[str, int],
        now: datetime | None = None,
        execution_binding_hash: str | None = None,
    ) -> dict[str, Any]:
        """Evaluate one request using broker-owned mutable security state."""
        now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)

        try:
            binding = _validate_execution_binding(execution_binding_hash)

            if self.revocation_checker is not None and self.revocation_checker(self.lease["lease_id"]):
                return self._reject(request, "lease_revoked", now, execution_binding_hash=binding)
            if now < self.not_before:
                return self._reject(request, "lease_not_yet_valid", now, execution_binding_hash=binding)
            if request["lease_id"] != self.lease["lease_id"]:
                return self._reject(request, "lease_binding", now, execution_binding_hash=binding)

            nonce = request["nonce"]
            if not isinstance(nonce, str) or len(nonce) < _MIN_NONCE_LENGTH:
                return self._reject(request, "invalid_nonce", now, execution_binding_hash=binding)
            if nonce in self.seen_nonces:
                return self._reject(request, "replay_nonce", now, execution_binding_hash=binding)

            sequence = request["sequence"]
            if not isinstance(sequence, int) or isinstance(sequence, bool):
                return self._reject(request, "invalid_sequence", now, execution_binding_hash=binding)
            if sequence != self.last_sequence + 1:
                return self._reject(request, "sequence_violation", now, execution_binding_hash=binding)

            request_time = parse_time(request["timestamp"])
            max_age = self.lease["max_request_age_seconds"]
            age_seconds = (now - request_time).total_seconds()
            if age_seconds < -30:
                return self._reject(request, "request_from_future", now, execution_binding_hash=binding)
            if age_seconds > max_age:
                return self._reject(request, "stale_request", now, execution_binding_hash=binding)

            delta = _validate_cost(cost)
            prospective = {name: self.usage[name] + delta[name] for name in USAGE_KEYS}

            gate_request = copy.deepcopy(request)
            gate_request.pop("lease_id", None)
            gate_request.pop("nonce", None)
            gate_request.pop("sequence", None)
            gate_request.pop("usage", None)
            gate_request["usage"] = dict(prospective)

            receipt = evaluate(self.policy, gate_request, now)
            receipt["policy_request_hash"] = receipt["request_hash"]
            receipt["request_hash"] = _hash(request)
            receipt["lease_id"] = self.lease["lease_id"]
            receipt["authoritative_usage"] = dict(prospective)
            if binding is not None:
                receipt["execution_binding_hash"] = binding

            # Structurally valid requests consume replay identity even on policy
            # denial; a denied request cannot later be replayed as new.
            self.seen_nonces.add(nonce)
            self.last_sequence = sequence

            if receipt["decision"] == "ALLOW":
                self.usage = dict(prospective)
            else:
                # Attempt accounting consumes the action counter but does not
                # fabricate effects that were never executed.
                self.usage["actions"] += delta["actions"]
                receipt["authoritative_usage"] = dict(self.usage)

            return self._chain(receipt)

        except (KeyError, TypeError, ValueError) as exc:
            # Invalid binding values are intentionally not copied into evidence.
            return self._reject(request, f"invalid_envelope:{type(exc).__name__}", now)

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
