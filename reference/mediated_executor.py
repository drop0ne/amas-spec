#!/usr/bin/env python3
"""AAB reference mediated execution binding.

A trusted adapter resolves the *effective* action and broker cost before
authorization. The AAB broker evaluates that prepared action. Only an ALLOW
decision permits the same immutable PreparedAction to reach adapter execution.

The acting model never supplies authoritative cost or effective adapter fields.
A production deployment must additionally ensure there is no second path to the
underlying tool, credential, network interface, subprocess, or equivalent effect.
"""
from __future__ import annotations

import copy
import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Mapping, Protocol

from enforcement_broker import USAGE_KEYS


class ExecutionBindingError(RuntimeError):
    """Fail-closed mediated-execution error."""


def _canonical_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def canonical_action_hash(obj: Any) -> str:
    return hashlib.sha256(_canonical_bytes(obj)).hexdigest()


def _json_clone(value: Any) -> Any:
    """Return a detached JSON value and reject non-JSON object types."""
    try:
        return json.loads(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
    except (TypeError, ValueError) as exc:
        raise ExecutionBindingError("prepared action must be JSON-serializable") from exc


def _validate_cost(cost: Mapping[str, Any]) -> dict[str, int]:
    if not isinstance(cost, Mapping) or set(cost) != set(USAGE_KEYS):
        raise ExecutionBindingError("adapter cost must contain exactly the broker usage fields")
    normalized: dict[str, int] = {}
    for name in USAGE_KEYS:
        value = cost[name]
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ExecutionBindingError(f"invalid adapter cost:{name}")
        normalized[name] = value
    if normalized["actions"] < 1:
        raise ExecutionBindingError("prepared execution must cost at least one action")
    return normalized


class PreparedAction:
    """Deeply immutable canonical adapter-resolved action.

    Nested dictionaries/lists are serialized at construction. Every property
    returns a fresh detached value, so neither caller nor adapter can mutate the
    descriptor that was hashed and authorized.
    """

    __slots__ = ("_adapter_id", "_payload_json", "_action_hash", "_sealed")

    def __init__(
        self,
        *,
        adapter_id: str,
        broker_request: Mapping[str, Any],
        parameters: Any,
        cost: Mapping[str, int],
    ):
        if not isinstance(adapter_id, str) or not adapter_id:
            raise ExecutionBindingError("adapter_id must be a non-empty string")
        payload = {
            "adapter_id": adapter_id,
            "broker_request": _json_clone(dict(broker_request)),
            "parameters": _json_clone(parameters),
            "cost": _validate_cost(cost),
        }
        payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        object.__setattr__(self, "_adapter_id", adapter_id)
        object.__setattr__(self, "_payload_json", payload_json)
        object.__setattr__(self, "_action_hash", hashlib.sha256(payload_json.encode("utf-8")).hexdigest())
        object.__setattr__(self, "_sealed", True)

    def __setattr__(self, name: str, value: Any) -> None:
        if getattr(self, "_sealed", False):
            raise AttributeError("PreparedAction is immutable")
        object.__setattr__(self, name, value)

    def _payload(self) -> dict[str, Any]:
        return json.loads(self._payload_json)

    @property
    def adapter_id(self) -> str:
        return self._adapter_id

    @property
    def broker_request(self) -> dict[str, Any]:
        return self._payload()["broker_request"]

    @property
    def parameters(self) -> Any:
        return self._payload()["parameters"]

    @property
    def cost(self) -> dict[str, int]:
        return self._payload()["cost"]

    def canonical_payload(self) -> dict[str, Any]:
        return self._payload()

    @property
    def action_hash(self) -> str:
        return self._action_hash


class TrustedAdapter(Protocol):
    """Adapter contract for a broker-mediated side-effect path."""

    adapter_id: str

    def prepare(self, request: Mapping[str, Any]) -> PreparedAction:
        """Resolve the effective target/destination/credential/effect and cost."""

    def execute(self, action: PreparedAction) -> Any:
        """Perform exactly the already-authorized prepared action."""


class AuthorizationBroker(Protocol):
    def authorize(self, request: dict[str, Any], *, cost: dict[str, int], now: datetime | None = None) -> dict[str, Any]:
        ...


_REQUIRED_BROKER_FIELDS = {
    "request_id",
    "lease_id",
    "nonce",
    "sequence",
    "principal",
    "objective_id",
    "operation",
    "target",
    "side_effect",
    "timestamp",
}

# A trusted adapter may resolve effective operation/target/destination/credential
# and side-effect class. It must not silently change authority/replay identity.
_BOUND_ENVELOPE_FIELDS = (
    "request_id",
    "lease_id",
    "nonce",
    "sequence",
    "principal",
    "objective_id",
    "timestamp",
)


class MediatedExecutor:
    """Prepare, authorize, and conditionally execute one trusted-adapter action."""

    def __init__(self, broker: AuthorizationBroker, adapters: Mapping[str, TrustedAdapter]):
        if not adapters:
            raise ValueError("at least one trusted adapter is required")
        self.broker = broker
        self._adapters: dict[str, TrustedAdapter] = {}
        for name, adapter in adapters.items():
            if not isinstance(name, str) or not name:
                raise ValueError("adapter registry keys must be non-empty strings")
            if adapter.adapter_id != name:
                raise ValueError("adapter registry key/id mismatch")
            self._adapters[name] = adapter

    def _prepare(self, request: Mapping[str, Any]) -> PreparedAction:
        adapter_id = request.get("adapter_id")
        if not isinstance(adapter_id, str) or adapter_id not in self._adapters:
            raise ExecutionBindingError("unknown adapter")

        # Detach model-supplied data before trusted preparation. Later caller
        # mutation therefore cannot change the request being resolved.
        model_request = _json_clone(dict(request))
        model_request.pop("adapter_id", None)
        adapter = self._adapters[adapter_id]
        prepared = adapter.prepare(model_request)
        if not isinstance(prepared, PreparedAction):
            raise ExecutionBindingError("adapter did not return PreparedAction")
        if prepared.adapter_id != adapter_id:
            raise ExecutionBindingError("prepared adapter identity mismatch")

        broker_request = prepared.broker_request
        missing = _REQUIRED_BROKER_FIELDS - set(broker_request)
        if missing:
            raise ExecutionBindingError(f"prepared broker request missing fields:{','.join(sorted(missing))}")

        for field in _BOUND_ENVELOPE_FIELDS:
            if broker_request.get(field) != model_request.get(field):
                raise ExecutionBindingError(f"prepared envelope mismatch:{field}")

        # Reconstruct once so adapter-provided PreparedAction cannot carry an
        # implementation-specific subclass or mutable wrapper into dispatch.
        return PreparedAction(
            adapter_id=adapter_id,
            broker_request=broker_request,
            parameters=prepared.parameters,
            cost=prepared.cost,
        )

    def execute(self, request: Mapping[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
        """Prepare, authorize, bind, and conditionally execute one action."""
        now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        try:
            prepared = self._prepare(request)
        except (ExecutionBindingError, TypeError, ValueError) as exc:
            return {
                "decision": "DENY",
                "reason": f"preparation_failed:{type(exc).__name__}",
                "executed": False,
                "action_hash": None,
                "authorization_receipt": None,
                "result": None,
            }

        action_hash = prepared.action_hash
        receipt = self.broker.authorize(prepared.broker_request, cost=prepared.cost, now=now)
        if not isinstance(receipt, dict):
            raise ExecutionBindingError("authorization broker returned invalid receipt")

        # Underlying AAB receipt stays independently hash-chained by the broker.
        # This detached field binds caller-visible authorization evidence to the
        # exact immutable descriptor that will be dispatched.
        authorization = copy.deepcopy(receipt)
        authorization["execution_binding_hash"] = action_hash

        if receipt.get("decision") != "ALLOW":
            return {
                "decision": receipt.get("decision", "DENY"),
                "reason": receipt.get("reason", "authorization_failed"),
                "executed": False,
                "action_hash": action_hash,
                "authorization_receipt": authorization,
                "result": None,
            }

        adapter = self._adapters[prepared.adapter_id]
        result = adapter.execute(prepared)
        return {
            "decision": "ALLOW",
            "reason": "authorized_and_executed",
            "executed": True,
            "action_hash": action_hash,
            "authorization_receipt": authorization,
            "result": _json_clone(result),
        }
