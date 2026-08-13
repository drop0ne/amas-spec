#!/usr/bin/env python3
"""AAB durable enforcement-state reference.

Adds authenticated crash-resistant state, cross-process transaction serialization,
state ancestry, and independently retained checkpoints to EnforcementBroker.
The acting model is not trusted with replay state, counters, receipt history,
lock ownership, or checkpoint keys.

This remains a reference mechanism, not a production storage/key-management
system. High-assurance deployments should move keys/checkpoints to independent
failure domains and use deployment-appropriate transactional storage.
"""
from __future__ import annotations

import copy
import hashlib
import hmac
import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator

from enforcement_broker import EnforcementBroker, USAGE_KEYS, _canonical_bytes
from receipt_chain import GENESIS, verify_chain


class DurabilityError(RuntimeError):
    """Fail-closed persistence, concurrency, or restoration error."""


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
    """EnforcementBroker with authenticated transactional durable state.

    Every authorization runs under a SQLite `BEGIN IMMEDIATE` sidecar lock,
    reloads the latest authenticated JSON state, evaluates, and persists before
    releasing the lock. This prevents two cooperating broker processes from
    authorizing against the same stale counters/sequence state.
    """

    STATE_VERSION = 2

    def __init__(
        self,
        lease: dict[str, Any],
        verification_key: bytes,
        *,
        state_path: str | Path,
        state_key: bytes,
        checkpoint: dict[str, Any] | None = None,
        checkpoint_key: bytes | None = None,
        revocation_checker: Callable[[str], bool] | None = None,
    ):
        self.state_path = Path(state_path)
        self.lock_path = self.state_path.with_name(self.state_path.name + ".lock.sqlite3")
        self.state_key = state_key
        self.state_generation = 0
        self.state_hash: str | None = None
        self.ancestor_state_hashes: list[str] = []
        self._checkpoint = copy.deepcopy(checkpoint)
        self._checkpoint_key = checkpoint_key
        self._poisoned = False
        super().__init__(lease, verification_key, revocation_checker=revocation_checker)

        with self._exclusive_state_transaction():
            if self.state_path.exists():
                self._restore(checkpoint=self._checkpoint, checkpoint_key=self._checkpoint_key)
            else:
                if checkpoint is not None:
                    raise DurabilityError("checkpoint exists but broker state is missing")
                self._persist()

    @contextmanager
    def _exclusive_state_transaction(self) -> Iterator[None]:
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            conn = sqlite3.connect(self.lock_path, timeout=5.0, isolation_level=None)
        except sqlite3.Error as exc:
            raise DurabilityError(f"state lock open failed:{type(exc).__name__}") from exc
        try:
            conn.execute("PRAGMA busy_timeout=5000")
            conn.execute("CREATE TABLE IF NOT EXISTS broker_lock (id INTEGER PRIMARY KEY CHECK (id = 1), marker INTEGER NOT NULL)")
            conn.execute("INSERT OR IGNORE INTO broker_lock(id, marker) VALUES (1, 0)")
            conn.execute("BEGIN IMMEDIATE")
            try:
                yield
            except Exception:
                conn.execute("ROLLBACK")
                raise
            else:
                conn.execute("COMMIT")
        except sqlite3.Error as exc:
            raise DurabilityError(f"state transaction failed:{type(exc).__name__}") from exc
        finally:
            conn.close()

    def _payload(self, generation: int) -> dict[str, Any]:
        verification = verify_chain(self.receipts)
        if not verification["valid"]:
            raise DurabilityError(f"receipt chain invalid:{verification.get('reason')}")
        ancestry = list(self.ancestor_state_hashes)
        previous = self.state_hash or GENESIS
        if self.state_hash is not None:
            ancestry.append(self.state_hash)
        return {
            "state_version": self.STATE_VERSION,
            "lease_id": self.lease["lease_id"],
            "policy_id": self.policy.get("policy_id"),
            "generation": generation,
            "previous_state_hash": previous,
            "ancestor_state_hashes": ancestry,
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
        self.ancestor_state_hashes = list(payload["ancestor_state_hashes"])

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
            previous_state_hash = envelope["previous_state_hash"]
            ancestry = envelope["ancestor_state_hashes"]
            last_sequence = envelope["last_sequence"]
            usage = envelope["usage"]
            nonces = envelope["seen_nonces"]
            receipts = envelope["receipts"]
            if not isinstance(generation, int) or isinstance(generation, bool) or generation < 1:
                raise ValueError("generation")
            if not isinstance(previous_state_hash, str) or len(previous_state_hash) != 64:
                raise ValueError("previous_state_hash")
            if not isinstance(ancestry, list) or any(not isinstance(h, str) or len(h) != 64 for h in ancestry):
                raise ValueError("ancestor_state_hashes")
            if len(ancestry) != generation - 1:
                raise ValueError("ancestry length")
            if generation == 1:
                if previous_state_hash != GENESIS or ancestry:
                    raise ValueError("generation-one ancestry")
            elif previous_state_hash != ancestry[-1]:
                raise ValueError("previous state hash does not match ancestry tip")
            if not isinstance(last_sequence, int) or isinstance(last_sequence, bool) or last_sequence < 0:
                raise ValueError("last_sequence")
            if not isinstance(usage, dict) or set(usage) != set(USAGE_KEYS):
                raise ValueError("usage")
            if any(not isinstance(usage[k], int) or isinstance(usage[k], bool) or usage[k] < 0 for k in USAGE_KEYS):
                raise ValueError("usage values")
            if not isinstance(nonces, list) or any(not isinstance(n, str) or len(n) < 16 for n in nonces):
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
        self.ancestor_state_hashes = list(ancestry)
        self.last_sequence = last_sequence
        self.usage = dict(usage)
        self.seen_nonces = set(nonces)
        self.receipts = copy.deepcopy(receipts)

        if checkpoint is not None:
            self._verify_checkpoint_ancestry(checkpoint, checkpoint_key, verification)

    def _verify_checkpoint_ancestry(
        self,
        checkpoint: dict[str, Any],
        checkpoint_key: bytes | None,
        verification: dict[str, Any],
    ) -> None:
        if checkpoint_key is None or not verify_checkpoint(checkpoint, checkpoint_key):
            raise DurabilityError("checkpoint signature verification failed")
        if checkpoint.get("lease_id") != self.lease["lease_id"]:
            raise DurabilityError("checkpoint lease mismatch")
        if checkpoint.get("policy_id") != self.policy.get("policy_id"):
            raise DurabilityError("checkpoint policy mismatch")
        checkpoint_generation = checkpoint.get("generation")
        if not isinstance(checkpoint_generation, int) or isinstance(checkpoint_generation, bool) or checkpoint_generation < 1:
            raise DurabilityError("invalid checkpoint generation")
        if self.state_generation < checkpoint_generation:
            raise DurabilityError("rollback detected: state generation behind checkpoint")

        checkpoint_hash = checkpoint.get("state_hash")
        checkpoint_tip = checkpoint.get("receipt_chain_tip")
        checkpoint_receipt_count = checkpoint.get("receipt_count")
        if not isinstance(checkpoint_receipt_count, int) or checkpoint_receipt_count < 0:
            raise DurabilityError("invalid checkpoint receipt count")

        if self.state_generation == checkpoint_generation:
            if checkpoint_hash != self.state_hash:
                raise DurabilityError("checkpoint/state hash mismatch")
            if checkpoint_tip != verification.get("chain_tip", GENESIS):
                raise DurabilityError("checkpoint/receipt tip mismatch")
            if checkpoint_receipt_count != len(self.receipts):
                raise DurabilityError("checkpoint/receipt count mismatch")
            return

        # Higher generation is accepted only if it explicitly descends from the
        # checkpointed state and its receipt chain extends the checkpoint tip.
        ancestor_index = checkpoint_generation - 1
        if ancestor_index >= len(self.ancestor_state_hashes) or self.ancestor_state_hashes[ancestor_index] != checkpoint_hash:
            raise DurabilityError("state fork detected: checkpoint is not an ancestor")
        if checkpoint_receipt_count > len(self.receipts):
            raise DurabilityError("checkpoint receipt count exceeds current chain")
        expected_tip = GENESIS if checkpoint_receipt_count == 0 else self.receipts[checkpoint_receipt_count - 1].get("receipt_hash")
        if expected_tip != checkpoint_tip:
            raise DurabilityError("receipt chain does not descend from checkpoint")

    def authorize(
        self,
        request: dict[str, Any],
        *,
        cost: dict[str, int],
        now: datetime | None = None,
        execution_binding_hash: str | None = None,
    ) -> dict[str, Any]:
        if self._poisoned:
            raise DurabilityError("broker instance is poisoned after persistence failure")
        with self._exclusive_state_transaction():
            # Another broker process may have advanced the state since this
            # object last ran. Reload while holding the transaction lock.
            if self.state_path.exists():
                self._restore(checkpoint=self._checkpoint, checkpoint_key=self._checkpoint_key)
            receipt = super().authorize(
                request,
                cost=cost,
                now=now,
                execution_binding_hash=execution_binding_hash,
            )
            try:
                self._persist()
            except Exception:
                self._poisoned = True
                raise
            return receipt

    def create_checkpoint(self, checkpoint_key: bytes, now: datetime | None = None) -> dict[str, Any]:
        with self._exclusive_state_transaction():
            if self.state_path.exists():
                self._restore(checkpoint=self._checkpoint, checkpoint_key=self._checkpoint_key)
            now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
            verification = verify_chain(self.receipts)
            if not verification["valid"] or self.state_hash is None:
                raise DurabilityError("cannot checkpoint invalid state")
            checkpoint = {
                "checkpoint_version": 2,
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
