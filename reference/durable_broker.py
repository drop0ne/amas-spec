#!/usr/bin/env python3
"""AMAS AAB 0.4 durable enforcement-state reference.

Adds crash-resistant broker state persistence and independently signable
checkpoints to the AAB 0.3 EnforcementBroker. The acting model is not trusted
with replay state, usage counters, receipt history, or checkpoint signing keys.

This is a reference mechanism, not a production storage or key-management
system. A production checkpoint should be anchored in a failure domain that an
agent controlling the broker host cannot rewrite (for example a remote
append-only log, transparency service, HSM-backed journal, or equivalent).
"""
from __future__ import annotations

import copy
import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from enforcement_broker import EnforcementBroker, USAGE_KEYS, _canonical_bytes
from receipt_chain import GENESIS, verify_chain


class DurabilityError(RuntimeError):
    """Fail-closed persistence or restoration error."""


def _sha256(obj: Any) -> str:
    return hashlib.sha256(_canonical_bytes(obj)).hexdigest()


def _mac(obj: Any, key: bytes) -> str:
    if not isinstance(key, bytes) or not key:
        raise ValueError("integrity key must be non-empty bytes")
    return hmac.new(key, _canonical_bytes(obj), hashlib.sha256).hexdigest()


def _atomic_write_json(path: Path, obj: Any) -> None:
    """Write JSON using fsync + atomic replace within one directory."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    data = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
    try:
        with tmp.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        try:
            fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        except OSError:
            # Directory fsync is not uniformly available on all platforms.
            pass
    finally:
        if tmp.exists():
            tmp.unlink(missing_ok=True)


def _unsigned_state(envelope: dict[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(envelope)
    out.pop("state_mac", None)
    return out


def _state_payload_for_hash(envelope: dict[str, Any]) -> dict[str, Any]:
    out = _unsigned_state(envelope)
    out.pop("state_hash", None)
    return out


def verify_state_envelope(envelope: dict[str, Any], state_key: bytes) -> bool:
    try:
        claimed_hash = envelope["state_hash"]
        claimed_mac = envelope["state_mac"]
        if not isinstance(claimed_hash, str) or not isinstance(claimed_mac, str):
            return False
        if claimed_hash != _sha256(_state_payload_for_hash(envelope)):
            return False
        return hmac.compare_digest(claimed_mac, _mac(_unsigned_state(envelope), state_key))
    except (KeyError, TypeError, ValueError):
        return False


def sign_checkpoint(checkpoint: dict[str, Any], key: bytes) -> dict[str, Any]:
    out = copy.deepcopy(checkpoint)
    out.pop("checkpoint_mac", None)
    out["checkpoint_mac"] = _mac(out, key)
    return out


def verify_checkpoint(checkpoint: dict[str, Any], key: bytes) -> bool:
    try:
        claimed = checkpoint["checkpoint_mac"]
        unsigned = copy.deepcopy(checkpoint)
        unsigned.pop("checkpoint_mac", None)
        return isinstance(claimed, str) and hmac.compare_digest(claimed, _mac(unsigned, key))
    except (KeyError, TypeError, ValueError):
        return False


class DurableEnforcementBroker(EnforcementBroker):
    """EnforcementBroker with authenticated durable security state.

    Authorization must not be treated as executable until this class returns
    successfully: every decision is persisted before return. A persistence
    exception is therefore a fail-closed outcome for the caller.
    """

    STATE_VERSION = 1

    def __init__(
        self,
        lease: dict[str, Any],
        verification_key: bytes,
        *,
        state_path: str | Path,
        state_key: bytes,
        checkpoint: dict[str, Any] | None = None,
        checkpoint_key: bytes | None = None,
    ):
        self.state_path = Path(state_path)
        self.state_key = state_key
        self.state_generation = 0
        self.state_hash: str | None = None
        super().__init__(lease, verification_key)

        if self.state_path.exists():
            self._restore(checkpoint=checkpoint, checkpoint_key=checkpoint_key)
        else:
            if checkpoint is not None:
                raise DurabilityError("checkpoint exists but broker state is missing")
            self._persist()

    def _payload(self, generation: int) -> dict[str, Any]:
        verification = verify_chain(self.receipts)
        if not verification["valid"]:
            raise DurabilityError(f"receipt chain invalid:{verification.get('reason')}")
        return {
            "state_version": self.STATE_VERSION,
            "lease_id": self.lease["lease_id"],
            "policy_id": self.policy.get("policy_id"),
            "generation": generation,
            "last_sequence": self.last_sequence,
            "usage": dict(self.usage),
            "seen_nonces": sorted(self.seen_nonces),
            "receipts": copy.deepcopy(self.receipts),
            "receipt_chain_tip": verification.get("chain_tip", GENESIS),
        }

    def _persist(self) -> None:
        generation = self.state_generation + 1
        payload = self._payload(generation)
        envelope = copy.deepcopy(payload)
        envelope["state_hash"] = _sha256(payload)
        envelope["state_mac"] = _mac(envelope, self.state_key)
        try:
            _atomic_write_json(self.state_path, envelope)
        except OSError as exc:
            raise DurabilityError(f"state persistence failed:{type(exc).__name__}") from exc
        self.state_generation = generation
        self.state_hash = envelope["state_hash"]

    def _restore(
        self,
        *,
        checkpoint: dict[str, Any] | None,
        checkpoint_key: bytes | None,
    ) -> None:
        try:
            envelope = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise DurabilityError(f"state read failed:{type(exc).__name__}") from exc

        if not isinstance(envelope, dict) or not verify_state_envelope(envelope, self.state_key):
            raise DurabilityError("state integrity verification failed")
        if envelope.get("state_version") != self.STATE_VERSION:
            raise DurabilityError("unsupported state version")
        if envelope.get("lease_id") != self.lease["lease_id"]:
            raise DurabilityError("state lease mismatch")
        if envelope.get("policy_id") != self.policy.get("policy_id"):
            raise DurabilityError("state policy mismatch")

        try:
            generation = envelope["generation"]
            last_sequence = envelope["last_sequence"]
            usage = envelope["usage"]
            nonces = envelope["seen_nonces"]
            receipts = envelope["receipts"]
            if not isinstance(generation, int) or generation < 1:
                raise ValueError("generation")
            if not isinstance(last_sequence, int) or last_sequence < 0:
                raise ValueError("last_sequence")
            if not isinstance(usage, dict) or set(usage) != set(USAGE_KEYS):
                raise ValueError("usage")
            if any(not isinstance(usage[k], int) or isinstance(usage[k], bool) or usage[k] < 0 for k in USAGE_KEYS):
                raise ValueError("usage values")
            if not isinstance(nonces, list) or any(not isinstance(n, str) or not n for n in nonces):
                raise ValueError("seen_nonces")
            if len(nonces) != len(set(nonces)):
                raise ValueError("duplicate nonce")
            if not isinstance(receipts, list):
                raise ValueError("receipts")
            verification = verify_chain(receipts)
            if not verification["valid"]:
                raise ValueError(f"receipt chain:{verification.get('reason')}")
            if envelope.get("receipt_chain_tip") != verification.get("chain_tip", GENESIS):
                raise ValueError("receipt chain tip")
        except (KeyError, TypeError, ValueError) as exc:
            raise DurabilityError(f"invalid persisted state:{exc}") from exc

        self.state_generation = generation
        self.state_hash = envelope["state_hash"]
        self.last_sequence = last_sequence
        self.usage = dict(usage)
        self.seen_nonces = set(nonces)
        self.receipts = copy.deepcopy(receipts)

        if checkpoint is not None:
            if checkpoint_key is None or not verify_checkpoint(checkpoint, checkpoint_key):
                raise DurabilityError("checkpoint signature verification failed")
            if checkpoint.get("lease_id") != self.lease["lease_id"]:
                raise DurabilityError("checkpoint lease mismatch")
            checkpoint_generation = checkpoint.get("generation")
            if not isinstance(checkpoint_generation, int):
                raise DurabilityError("invalid checkpoint generation")
            if self.state_generation < checkpoint_generation:
                raise DurabilityError("rollback detected: state generation behind checkpoint")
            if self.state_generation == checkpoint_generation:
                if checkpoint.get("state_hash") != self.state_hash:
                    raise DurabilityError("checkpoint/state hash mismatch")
                if checkpoint.get("receipt_chain_tip") != verification.get("chain_tip", GENESIS):
                    raise DurabilityError("checkpoint/receipt tip mismatch")

    def authorize(self, request: dict[str, Any], *, cost: dict[str, int], now: datetime | None = None) -> dict[str, Any]:
        receipt = super().authorize(request, cost=cost, now=now)
        self._persist()
        return receipt

    def create_checkpoint(self, checkpoint_key: bytes, now: datetime | None = None) -> dict[str, Any]:
        now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        verification = verify_chain(self.receipts)
        if not verification["valid"] or self.state_hash is None:
            raise DurabilityError("cannot checkpoint invalid state")
        checkpoint = {
            "checkpoint_version": 1,
            "lease_id": self.lease["lease_id"],
            "policy_id": self.policy.get("policy_id"),
            "generation": self.state_generation,
            "state_hash": self.state_hash,
            "receipt_count": len(self.receipts),
            "receipt_chain_tip": verification.get("chain_tip", GENESIS),
            "checkpointed_at": now.isoformat().replace("+00:00", "Z"),
            "signature_alg": "HMAC-SHA256",
        }
        return sign_checkpoint(checkpoint, checkpoint_key)

    def write_checkpoint(self, path: str | Path, checkpoint_key: bytes, now: datetime | None = None) -> dict[str, Any]:
        checkpoint = self.create_checkpoint(checkpoint_key, now=now)
        try:
            _atomic_write_json(Path(path), checkpoint)
        except OSError as exc:
            raise DurabilityError(f"checkpoint persistence failed:{type(exc).__name__}") from exc
        return checkpoint
