#!/usr/bin/env python3
"""AAB reference mediated execution binding.

This module closes a narrow authorize-then-execute seam in the reference stack.
A trusted adapter first resolves the *effective* action and broker cost. The AAB
broker authorizes that prepared action. Only an ALLOW decision permits the same
prepared object to reach the adapter's execute method.

The acting model never supplies authoritative cost or effective adapter fields,
and a denied preparation is never executed.

This is still an in-process reference mechanism. A production deployment must
ensure the model/caller has no second path to the underlying adapter, credential,
network interface, subprocess, or equivalent side effect.
"""
from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass
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
    """Return a detached JSON value and reject non-canonical object types."""
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


@dataclass(frozen=True)
class PreparedAction:
    """Immutable adapter-resolved action presented to the authorization broker."""

    adapter_id: str
    broker_request: Mapping[str, Any]
    parameters: Any
    cost: Mapping[str, int]

    def canonical_payload(self) -> dict[str, Any]:
        return {
            "adapter_id": self.adapter_id,
            "broker_request": _json_clone(dict(self.broker_request)),
            "parameters": _json_clone(self.parameters),
            "cost": _validate_cost(self.cost),
        }

    @property
    def action_hash(self) -> str:
        return canonical_action_hash(self.canonical_payload())


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

# Envelope fields establish the replay/freshness identity of the model request.
# A trusted adapter may resolve effective operation/target/destination/credential
# and side-effect class, but it must not silently change the request's authority
# identity or replay envelope.
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
    """Authorize and execute one adapter-prepared action as a single code path.

    Callers provide an agent request and select a registered adapter. The adapter
    resolves the effective action. The broker evaluates those effective fields.
    The same immutable PreparedAction object is then passed to execute only when
    the decision is ALLOW.
    """

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

        # Detach model-supplied data before a trusted adapter sees it so later
        # caller mutation cannot alter the preparation being authorized.
        model_request = _json_clone(dict(request))
        model_request.pop("adapter_id", None)
        adapter = self._adapters[adapter_id]
        prepared = adapter.prepare(model_request)
        if not isinstance(prepared, PreparedAction):
            raise ExecutionBindingError("adapter did not return PreparedAction")
        if prepared.adapter_id != adapter_id:
            raise ExecutionBindingError("prepared adapter identity mismatch")

        broker_request = _json_clone(dict(prepared.broker_request))
        missing = _REQUIRED_BROKER_FIELDS - set(broker_request)
        if missing:
            raise ExecutionBindingError(f"prepared broker request missing fields:{','.join(sorted(missing))}")

        # Prevent a trusted-adapter bug from switching replay/principal/objective
        # identity while still allowing it to resolve the effective action.
        for field in _BOUND_ENVELOPE_FIELDS:
            if broker_request.get(field) != model_request.get(field):
                raise ExecutionBindingError(f"prepared envelope mismatch:{field}")

        cost = _validate_cost(prepared.cost)
        parameters = _json_clone(prepared.parameters)
        return PreparedAction(
            adapter_id=adapter_id,
            broker_request=broker_request,
            parameters=parameters,
            cost=cost,
        )

    def execute(self, request: Mapping[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
        """Prepare, authorize, durably bind, and conditionally execute one action."""
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
        broker_request = _json_clone(dict(prepared.broker_request))
        receipt = self.broker.authorize(broker_request, cost=dict(prepared.cost), now=now)
        if not isinstance(receipt, dict):
            raise ExecutionBindingError("authorization broker returned invalid receipt")

        # Bind the exact prepared descriptor into the caller-visible receipt.
        # The underlying AAB receipt remains independently hash-chained by the
        # broker; this field is an execution binding, not a rewrite of that hash.
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
