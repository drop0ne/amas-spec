#!/usr/bin/env python3
"""AMAS AAB 0.3 reference enforcement broker.

This module demonstrates controls that must live outside the acting model:
- signed authority leases
- replay-resistant request nonces and monotonic sequence numbers
- broker-owned cumulative usage accounting
- request freshness checks
- fail-closed policy evaluation
- tamper-evident decision receipt chaining

The broker authorizes requests only; it does not execute external actions.
HMAC-SHA256 is used as a compact reference signing mechanism. Production
systems should normally use a dedicated key-management system and an
asymmetric or otherwise deployment-appropriate authentication scheme.
"""
from __future__ import annotations

import copy
import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Any

from authority_gate import evaluate, parse_time
from receipt_chain import append_receipt, verify_chain

USAGE_KEYS = ("actions", "network_calls", "egress_bytes", "wall_clock_seconds")


def _canonical_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


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


class EnforcementBroker:
    """Stateful AAB authorization boundary.

    Important reference assumption: `cost` is trusted broker/adapter metadata,
    not an agent-controlled claim. A production broker should compute or bind
    these charges from the tool invocation it is about to perform.
    """

    def __init__(self, lease: dict[str, Any], verification_key: bytes):
        if not verify_lease_signature(lease, verification_key):
            raise ValueError("invalid lease signature")
        if lease.get("signature_alg") != "HMAC-SHA256":
            raise ValueError("unsupported signature algorithm")
        if not isinstance(lease.get("lease_id"), str) or not lease["lease_id"]:
            raise ValueError("invalid lease_id")
        if not isinstance(lease.get("issuer"), str) or not lease["issuer"]:
            raise ValueError("invalid issuer")
        parse_time(lease["issued_at"])
        if not isinstance(lease.get("max_request_age_seconds"), int) or lease["max_request_age_seconds"] < 0:
            raise ValueError("invalid max_request_age_seconds")
        if not isinstance(lease.get("policy"), dict):
            raise ValueError("missing policy")

        self.lease = copy.deepcopy(lease)
        self.policy = copy.deepcopy(lease["policy"])
        self.usage = _zero_usage()
        self.seen_nonces: set[str] = set()
        self.last_sequence = 0
        self.receipts: list[dict[str, Any]] = []

    def _reject(self, request: dict[str, Any], reason: str, now: datetime) -> dict[str, Any]:
        receipt = {
            "request_id": request.get("request_id", "UNKNOWN"),
            "policy_id": self.policy.get("policy_id", "UNKNOWN"),
            "decision": "DENY",
            "reason": reason,
            "evaluated_at": now.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
            "policy_hash": hashlib.sha256(_canonical_bytes(self.policy)).hexdigest(),
            "request_hash": hashlib.sha256(_canonical_bytes(request)).hexdigest(),
            "lease_id": self.lease["lease_id"],
            "authoritative_usage": dict(self.usage),
        }
        chained = append_receipt(self.receipts, receipt)
        self.receipts.append(chained)
        return chained

    def authorize(self, request: dict[str, Any], *, cost: dict[str, int], now: datetime | None = None) -> dict[str, Any]:
        """Evaluate one request using broker-owned mutable security state."""
        now = now or datetime.now(timezone.utc)
        now = now.astimezone(timezone.utc)

        try:
            if request["lease_id"] != self.lease["lease_id"]:
                return self._reject(request, "lease_binding", now)

            nonce = request["nonce"]
            if not isinstance(nonce, str) or not nonce:
                return self._reject(request, "invalid_nonce", now)
            if nonce in self.seen_nonces:
                return self._reject(request, "replay_nonce", now)

            sequence = request["sequence"]
            if not isinstance(sequence, int) or isinstance(sequence, bool):
                return self._reject(request, "invalid_sequence", now)
            if sequence != self.last_sequence + 1:
                return self._reject(request, "sequence_violation", now)

            request_time = parse_time(request["timestamp"])
            max_age = self.lease["max_request_age_seconds"]
            age_seconds = (now - request_time).total_seconds()
            if age_seconds < -30:
                return self._reject(request, "request_from_future", now)
            if age_seconds > max_age:
                return self._reject(request, "stale_request", now)

            delta = _validate_cost(cost)
            prospective = {name: self.usage[name] + delta[name] for name in USAGE_KEYS}

            gate_request = copy.deepcopy(request)
            gate_request.pop("lease_id", None)
            gate_request.pop("nonce", None)
            gate_request.pop("sequence", None)
            gate_request["usage"] = prospective

            receipt = evaluate(self.policy, gate_request, now)
            receipt["lease_id"] = self.lease["lease_id"]
            receipt["authoritative_usage"] = prospective

            # Once a structurally valid request reaches policy evaluation, its
            # sequence/nonce are consumed even if the policy denies it. This
            # prevents replaying a denied request as though it were new.
            self.seen_nonces.add(nonce)
            self.last_sequence = sequence

            if receipt["decision"] == "ALLOW":
                self.usage = prospective
            else:
                # Attempted actions consume the action counter, but do not
                # consume side-effect/network/egress/time budgets unless the
                # broker actually performs those effects. This is explicit and
                # conservative rather than trusting agent-reported totals.
                self.usage["actions"] += delta["actions"]
                receipt["authoritative_usage"] = dict(self.usage)

            chained = append_receipt(self.receipts, receipt)
            self.receipts.append(chained)
            return chained

        except (KeyError, TypeError, ValueError) as exc:
            return self._reject(request, f"invalid_envelope:{type(exc).__name__}", now)

    def verify_receipts(self) -> bool:
        return verify_chain(self.receipts)

    def snapshot(self) -> dict[str, Any]:
        return {
            "lease_id": self.lease["lease_id"],
            "policy_id": self.policy.get("policy_id"),
            "last_sequence": self.last_sequence,
            "usage": dict(self.usage),
            "seen_nonce_count": len(self.seen_nonces),
            "receipt_count": len(self.receipts),
            "receipt_chain_valid": self.verify_receipts(),
        }
