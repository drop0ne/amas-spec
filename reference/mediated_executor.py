#!/usr/bin/env python3
"""AAB mediated authorization-to-execution binding.

A trusted adapter resolves the effective action, capability contract, security-
relevant effects, and broker cost before authorization. The exact immutable
PreparedAction hash is passed into the broker and is covered by the broker's
tamper-evident receipt chain. Only a receipt carrying the same binding hash may
release the prepared action to execution.
"""
from __future__ import annotations

import copy
import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Mapping, Protocol

from capability_contract import CapabilityContractError, validate_prepared_action
from enforcement_broker import USAGE_KEYS


class ExecutionBindingError(RuntimeError):
    """Fail-closed mediated-execution error."""


def _canonical_bytes(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def canonical_action_hash(obj: Any) -> str:
    return hashlib.sha256(_canonical_bytes(obj)).hexdigest()


def _json_clone(value: Any) -> Any:
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


def _empty_security_effects() -> dict[str, list[str]]:
    return {
        "redirect_chain": [],
        "filesystem_paths": [],
        "subprocesses": [],
        "secondary_destinations": [],
    }


def _validate_security_effects(value: Mapping[str, Any] | None) -> dict[str, list[str]]:
    effects = _empty_security_effects() if value is None else _json_clone(dict(value))
    if set(effects) != set(_empty_security_effects()):
        raise ExecutionBindingError("security_effects must contain exactly the required effect classes")
    for key, items in effects.items():
        if not isinstance(items, list) or any(not isinstance(item, str) or not item for item in items):
            raise ExecutionBindingError(f"invalid security_effects:{key}")
    return effects


class PreparedAction:
    """Deeply immutable canonical adapter-resolved action."""

    __slots__ = ("_adapter_id", "_payload_json", "_action_hash", "_sealed")

    def __init__(
        self,
        *,
        adapter_id: str,
        broker_request: Mapping[str, Any],
        parameters: Any,
        cost: Mapping[str, int],
        security_effects: Mapping[str, Any] | None = None,
    ):
        if not isinstance(adapter_id, str) or not adapter_id:
            raise ExecutionBindingError("adapter_id must be a non-empty string")
        payload = {
            "adapter_id": adapter_id,
            "broker_request": _json_clone(dict(broker_request)),
            "parameters": _json_clone(parameters),
            "cost": _validate_cost(cost),
            "security_effects": _validate_security_effects(security_effects),
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

    @property
    def security_effects(self) -> dict[str, list[str]]:
        return self._payload()["security_effects"]

    def canonical_payload(self) -> dict[str, Any]:
        return self._payload()

    @property
    def action_hash(self) -> str:
        return self._action_hash


class TrustedAdapter(Protocol):
    adapter_id: str

    def prepare(self, request: Mapping[str, Any]) -> PreparedAction:
        """Resolve the effective action, effects, and cost."""

    def execute(self, action: PreparedAction) -> Any:
        """Perform exactly the already-authorized prepared action."""


class AuthorizationBroker(Protocol):
    def authorize(
        self,
        request: dict[str, Any],
        *,
        cost: dict[str, int],
        now: datetime | None = None,
        execution_binding_hash: str | None = None,
    ) -> dict[str, Any]: ...


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
    """Prepare, contract-check, authorize, and execute one mediated action."""

    def __init__(
        self,
        broker: AuthorizationBroker,
        adapters: Mapping[str, TrustedAdapter],
        capability_contracts: Mapping[str, Mapping[str, Any]] | None = None,
    ):
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
        self._contracts = {str(key): _json_clone(dict(value)) for key, value in (capability_contracts or {}).items()}

    def _prepare(self, request: Mapping[str, Any]) -> PreparedAction:
        adapter_id = request.get("adapter_id")
        if not isinstance(adapter_id, str) or adapter_id not in self._adapters:
            raise ExecutionBindingError("unknown adapter")

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

        # Reconstruct into the exact trusted base class, detaching any adapter
        # subclass/wrapper before policy evaluation and dispatch.
        action = PreparedAction(
            adapter_id=adapter_id,
            broker_request=broker_request,
            parameters=prepared.parameters,
            cost=prepared.cost,
            security_effects=prepared.security_effects,
        )

        contract_id = action.broker_request.get("capability_contract_id")
        if contract_id is not None:
            if not isinstance(contract_id, str) or contract_id not in self._contracts:
                raise ExecutionBindingError("unknown capability contract")
            try:
                validate_prepared_action(self._contracts[contract_id], action)
            except CapabilityContractError as exc:
                raise ExecutionBindingError(f"capability contract denied:{exc}") from exc
        elif self._contracts:
            # A configured mediated executor does not silently drop from
            # parameter/effect enforcement to coarse authorization.
            raise ExecutionBindingError("capability contract missing")

        return action

    def execute(self, request: Mapping[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
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
        receipt = self.broker.authorize(
            prepared.broker_request,
            cost=prepared.cost,
            now=now,
            execution_binding_hash=action_hash,
        )
        if not isinstance(receipt, dict):
            raise ExecutionBindingError("authorization broker returned invalid receipt")

        # The binding must be inside the broker-signed/chained receipt, not
        # appended by caller code afterward.
        if receipt.get("execution_binding_hash") != action_hash:
            return {
                "decision": "DENY",
                "reason": "authorization_binding_mismatch",
                "executed": False,
                "action_hash": action_hash,
                "authorization_receipt": copy.deepcopy(receipt),
                "result": None,
            }

        authorization = copy.deepcopy(receipt)
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
