from __future__ import annotations

import base64
import hashlib
import hmac
import multiprocessing
import secrets
from typing import Any

_HASH_LEN = 64
_COMPLETION_TRANSITIONS = {
    None: {"STARTED"},
    "STARTED": {"SUCCEEDED", "FAILED_NO_EFFECT", "OUTCOME_UNKNOWN"},
    "OUTCOME_UNKNOWN": {"EFFECT_CONFIRMED", "NO_EFFECT_CONFIRMED"},
    "SUCCEEDED": set(),
    "FAILED_NO_EFFECT": set(),
    "EFFECT_CONFIRMED": set(),
    "NO_EFFECT_CONFIRMED": set(),
}


class TrustBoundaryError(RuntimeError):
    pass


class TrustBoundaryUnavailable(TrustBoundaryError):
    pass


def _require_id(value: str, name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 256:
        raise ValueError(f"invalid {name}")
    return value


def _require_hash(value: str, name: str) -> str:
    if not isinstance(value, str) or len(value) != _HASH_LEN or any(ch not in "0123456789abcdef" for ch in value):
        raise ValueError(f"invalid {name}")
    return value


def _require_generation(value: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1 or value > 9007199254740991:
        raise ValueError("invalid generation")
    return value


def _identity_token(secret: bytes, principal: str, nonce: bytes) -> str:
    payload = principal.encode("utf-8") + b"\x00" + nonce
    mac = hmac.new(secret, payload, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(nonce + mac).decode("ascii").rstrip("=")


def _decode_token(token: str) -> bytes:
    if not isinstance(token, str) or not token:
        raise ValueError("invalid identity token")
    padding = "=" * (-len(token) % 4)
    try:
        raw = base64.urlsafe_b64decode(token + padding)
    except Exception as exc:
        raise ValueError("invalid identity token") from exc
    if len(raw) != 48:
        raise ValueError("invalid identity token")
    return raw


class LocalTrustBoundary:
    """Same-process reference store. Useful for tests, not independent-failure-domain evidence."""

    def __init__(self, *, identity_secret: bytes | None = None) -> None:
        self._checkpoints: dict[str, tuple[str, int]] = {}
        self._revoked: set[str] = set()
        self._completion: dict[str, dict[str, str]] = {}
        self._identity_secret = identity_secret or secrets.token_bytes(32)

    def anchor_checkpoint(self, checkpoint_id: str, state_hash: str, generation: int) -> dict[str, Any]:
        checkpoint_id = _require_id(checkpoint_id, "checkpoint_id")
        state_hash = _require_hash(state_hash, "state_hash")
        generation = _require_generation(generation)
        value = (state_hash, generation)
        prior = self._checkpoints.get(checkpoint_id)
        if prior is not None and prior != value:
            raise TrustBoundaryError("checkpoint anchor is immutable")
        self._checkpoints[checkpoint_id] = value
        return {"checkpoint_id": checkpoint_id, "state_hash": state_hash, "generation": generation}

    def checkpoint_matches(self, checkpoint_id: str, state_hash: str, generation: int) -> bool:
        return self._checkpoints.get(_require_id(checkpoint_id, "checkpoint_id")) == (
            _require_hash(state_hash, "state_hash"), _require_generation(generation)
        )

    def revoke(self, lease_id: str) -> None:
        self._revoked.add(_require_id(lease_id, "lease_id"))

    def is_revoked(self, lease_id: str) -> bool:
        return _require_id(lease_id, "lease_id") in self._revoked

    def record_completion(self, execution_id: str, action_hash: str, state: str) -> dict[str, str]:
        execution_id = _require_hash(execution_id, "execution_id")
        action_hash = _require_hash(action_hash, "action_hash")
        if state not in _COMPLETION_TRANSITIONS:
            raise ValueError("invalid completion state")
        prior = self._completion.get(execution_id)
        prior_state = None if prior is None else prior["state"]
        if prior is not None and prior["action_hash"] != action_hash:
            raise TrustBoundaryError("completion action hash mismatch")
        if state not in _COMPLETION_TRANSITIONS[prior_state]:
            raise TrustBoundaryError(f"invalid completion transition:{prior_state}->{state}")
        record = {"execution_id": execution_id, "action_hash": action_hash, "state": state}
        self._completion[execution_id] = record
        return dict(record)

    def get_completion(self, execution_id: str) -> dict[str, str] | None:
        value = self._completion.get(_require_hash(execution_id, "execution_id"))
        return None if value is None else dict(value)

    def issue_identity(self, principal: str) -> dict[str, str]:
        principal = _require_id(principal, "principal")
        nonce = secrets.token_bytes(16)
        return {"principal": principal, "token": _identity_token(self._identity_secret, principal, nonce)}

    def verify_identity(self, principal: str, token: str) -> bool:
        principal = _require_id(principal, "principal")
        raw = _decode_token(token)
        nonce, claimed = raw[:16], raw[16:]
        expected = hmac.new(self._identity_secret, principal.encode("utf-8") + b"\x00" + nonce, hashlib.sha256).digest()
        return hmac.compare_digest(claimed, expected)


def _service_main(conn: Any) -> None:
    store = LocalTrustBoundary()
    conn.send({"ready": True})
    while True:
        try:
            message = conn.recv()
        except EOFError:
            return
        command = message.get("command")
        if command == "close":
            conn.send({"ok": True, "value": None})
            return
        args = message.get("args", [])
        try:
            method = getattr(store, command)
            value = method(*args)
            conn.send({"ok": True, "value": value})
        except Exception as exc:
            conn.send({"ok": False, "error_type": type(exc).__name__, "error": str(exc)})


class ProcessTrustBoundary:
    """Same-host separate-process reference trust service.

    The acting caller has no direct reference to the service's mutable state or
    identity secret. This is stronger isolation than LocalTrustBoundary but is
    not an independent host/HSM/service failure domain and is not A4 evidence.
    """

    def __init__(self) -> None:
        ctx = multiprocessing.get_context("spawn")
        parent, child = ctx.Pipe()
        self._conn = parent
        self._process = ctx.Process(target=_service_main, args=(child,), daemon=True)
        self._process.start()
        child.close()
        if not self._conn.poll(10):
            self.close(force=True)
            raise TrustBoundaryUnavailable("trust service did not become ready")
        if self._conn.recv() != {"ready": True}:
            self.close(force=True)
            raise TrustBoundaryUnavailable("invalid trust service readiness response")

    def _call(self, command: str, *args: Any) -> Any:
        if self._process is None or not self._process.is_alive():
            raise TrustBoundaryUnavailable("trust service unavailable")
        try:
            self._conn.send({"command": command, "args": list(args)})
            if not self._conn.poll(10):
                raise TrustBoundaryUnavailable("trust service response timeout")
            response = self._conn.recv()
        except (BrokenPipeError, EOFError, OSError) as exc:
            raise TrustBoundaryUnavailable("trust service transport failed") from exc
        if not response.get("ok"):
            raise TrustBoundaryError(f"{response.get('error_type')}:{response.get('error')}")
        return response.get("value")

    def anchor_checkpoint(self, checkpoint_id: str, state_hash: str, generation: int) -> dict[str, Any]:
        return self._call("anchor_checkpoint", checkpoint_id, state_hash, generation)

    def checkpoint_matches(self, checkpoint_id: str, state_hash: str, generation: int) -> bool:
        return bool(self._call("checkpoint_matches", checkpoint_id, state_hash, generation))

    def revoke(self, lease_id: str) -> None:
        self._call("revoke", lease_id)

    def is_revoked(self, lease_id: str) -> bool:
        return bool(self._call("is_revoked", lease_id))

    def record_completion(self, execution_id: str, action_hash: str, state: str) -> dict[str, str]:
        return self._call("record_completion", execution_id, action_hash, state)

    def get_completion(self, execution_id: str) -> dict[str, str] | None:
        return self._call("get_completion", execution_id)

    def issue_identity(self, principal: str) -> dict[str, str]:
        return self._call("issue_identity", principal)

    def verify_identity(self, principal: str, token: str) -> bool:
        return bool(self._call("verify_identity", principal, token))

    def terminate_for_test(self) -> None:
        if self._process is not None and self._process.is_alive():
            self._process.terminate()
            self._process.join(timeout=5)

    def close(self, *, force: bool = False) -> None:
        process = getattr(self, "_process", None)
        if process is None:
            return
        if process.is_alive() and not force:
            try:
                self._call("close")
            except TrustBoundaryError:
                pass
        if process.is_alive():
            process.terminate()
        process.join(timeout=5)
        try:
            self._conn.close()
        except OSError:
            pass
        self._process = None

    def __enter__(self) -> "ProcessTrustBoundary":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()
