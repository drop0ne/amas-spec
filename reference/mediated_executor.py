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
import json
from datetime import datetime, timezone
from typing import Any, Mapping, Protocol

from canonical_json import CanonicalJSONError, MAX_SAFE_INTEGER, dumps as canonical_dumps, sha256 as canonical_sha256, validate as validate_canonical
from capability_contract import CapabilityContractError, validate_prepared_action, verify_contract_identity
from enforcement_broker import USAGE_KEYS


class ExecutionBindingError(RuntimeError):
    """Fail-closed mediated-execution error."""


def canonical_action_hash(obj: Any) -> str:
    try:
        return canonical_sha256(obj)
    except CanonicalJSONError as exc:
        raise ExecutionBindingError("prepared action is not Canonical JSON v1") from exc


def _security_clone(value: Any) -> Any:
    try:
        # Canonical serialization is both validation and a deep-copy boundary.
        return json.loads(canonical_dumps(value))
    except (CanonicalJSONError, json.JSONDecodeError, RecursionError) as exc:
        raise ExecutionBindingError("prepared security object must satisfy Canonical JSON v1") from exc


def _result_clone(value: Any) -> Any:
    try:
        return json.loads(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False))
    except (TypeError, ValueError, json.JSONDecodeError, RecursionError) as exc:
        raise ExecutionBindingError("adapter result must be finite JSON") from exc


def _validate_cost(cost: Mapping[str, Any]) -> dict[str, int]:
    if not isinstance(cost, Mapping) or set(cost) != set(USAGE_KEYS):
        raise ExecutionBindingError("adapter cost must contain exactly the broker usage fields")
    normalized: dict[str, int] = {}
    for name in USAGE_KEYS:
        value = cost[name]
        if not isinstance(value, int) or isinstance(value, bool) or value < 0 or value > MAX_SAFE_INTEGER:
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
    effects = _empty_security_effects() if value is None else _security_clone(dict(value))
    if set(effects) != set(_empty_security_effects()):
        raise ExecutionBindingError("security_effects must contain exactly the required effect classes")
    for key, items in effects.items():
        if not isinstance(items, list) or any(not isinstance(item, str) or not item for item in items):
            raise ExecutionBindingError(f"invalid security_effects:{key}")
        if len(items) != len(set(items)):
            raise ExecutionBindingError(f"duplicate security_effects:{key}")
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
            "broker_request": _security_clone(dict(broker_request)),
            "parameters": _security_clone(parameters),
            "cost": _validate_cost(cost),
            "security_effects": _validate_security_effects(security_effects),
        }
        try:
            validate_canonical(payload)
            payload_json = canonical_dumps(payload)
            action_hash = canonical_sha256(payload)
        except CanonicalJSONError as exc:
            raise ExecutionBindingError("prepared action is not Canonical JSON v1") from exc
        object.__setattr__(self, "_adapter_id", adapter_id)
        object.__setattr__(self, "_payload_json", payload_json)
        object.__setattr__(self, "_action_hash", action_hash)
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

        self._contracts: dict[str, dict[str, Any]] = {}
        for key, value in (capability_contracts or {}).items():
            if not isinstance(key, str) or not isinstance(value, Mapping):
                raise ValueError("invalid capability contract registry entry")
            cloned = _security_clone(dict(value))
            if cloned.get("contract_id") != key or not verify_contract_identity(cloned):
                raise ValueError("capability contract registry key/content identity mismatch")
            self._contracts[key] = cloned

    def _prepare(self, request: Mapping[str, Any]) -> PreparedAction:
        if not isinstance(request, Mapping):
            raise ExecutionBindingError("request must be an object")
        adapter_id = request.get("adapter_id")
        if not isinstance(adapter_id, str) or adapter_id not in self._adapters:
            raise ExecutionBindingError("unknown adapter")

        model_request = _security_clone(dict(request))
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
            raise ExecutionBindingError("capability contract missing")

        return action

    def execute(self, request: Mapping[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
        now = now or datetime.now(timezone.utc)
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
        else:
            now = now.astimezone(timezone.utc)
        try:
            prepared = self._prepare(request)
        except (ExecutionBindingError, CanonicalJSONError, TypeError, ValueError, RecursionError) as exc:
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
            "result": _result_clone(result),
        }
