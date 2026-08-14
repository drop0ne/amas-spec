#!/usr/bin/env python3
"""AAB mediated authorization-to-execution binding.

A trusted adapter resolves the effective action, capability contract, security-
relevant effects, and broker cost before authorization. The exact immutable
PreparedAction hash is passed into the broker and covered by the broker receipt
chain.

Authorization and completion are distinct facts. Before an ALLOWed adapter call
is dispatched, the executor writes a transactional STARTED record. The record is
then finalized as SUCCEEDED or OUTCOME_UNKNOWN. A lingering STARTED record is
interpreted as OUTCOME_UNKNOWN, never as proof that no effect occurred.
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Protocol

from canonical_json import CanonicalJSONError, MAX_SAFE_INTEGER, dumps as canonical_dumps, sha256 as canonical_sha256, validate as validate_canonical
from capability_contract import CapabilityContractError, validate_prepared_action, verify_contract_identity
from enforcement_broker import USAGE_KEYS


class ExecutionBindingError(RuntimeError):
    """Fail-closed mediated-execution error."""


class CompletionJournalError(RuntimeError):
    """Fail-closed completion-state persistence error."""


_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_FINAL_COMPLETION_STATES = {"SUCCEEDED", "OUTCOME_UNKNOWN"}


def canonical_action_hash(obj: Any) -> str:
    try:
        return canonical_sha256(obj)
    except CanonicalJSONError as exc:
        raise ExecutionBindingError("prepared action is not Canonical JSON v1") from exc


def _security_clone(value: Any) -> Any:
    try:
        return json.loads(canonical_dumps(value))
    except (CanonicalJSONError, json.JSONDecodeError, RecursionError) as exc:
        raise ExecutionBindingError("prepared security object must satisfy Canonical JSON v1") from exc


def _result_clone(value: Any) -> Any:
    try:
        return json.loads(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False))
    except (TypeError, ValueError, json.JSONDecodeError, RecursionError) as exc:
        raise ExecutionBindingError("adapter result must be finite JSON") from exc


def _result_hash(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


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


def _utc_text(value: datetime | None = None) -> str:
    now = value or datetime.now(timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    return now.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _require_hash(value: str, name: str) -> str:
    if not isinstance(value, str) or _HASH_RE.fullmatch(value) is None:
        raise CompletionJournalError(f"{name} must be lowercase SHA-256 hex")
    return value


def execution_id_for(receipt_hash: str, action_hash: str) -> str:
    return canonical_sha256({
        "authorization_receipt_hash": _require_hash(receipt_hash, "authorization_receipt_hash"),
        "action_hash": _require_hash(action_hash, "action_hash"),
    })


class SQLiteCompletionJournal:
    """Transactional journal for adapter-dispatch completion state.

    A filesystem database with `synchronous=FULL` is the durable reference mode.
    `:memory:` exists for tests only and MUST NOT be described as crash durable.
    """

    def __init__(self, path: str | Path):
        self.path = str(path)
        try:
            self._conn = sqlite3.connect(self.path, timeout=5.0, isolation_level=None)
            self._conn.execute("PRAGMA busy_timeout=5000")
            if self.path != ":memory:":
                self._conn.execute("PRAGMA journal_mode=WAL")
                self._conn.execute("PRAGMA synchronous=FULL")
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS effect_completion ("
                "execution_id TEXT PRIMARY KEY,"
                "authorization_receipt_hash TEXT NOT NULL UNIQUE,"
                "action_hash TEXT NOT NULL,"
                "status TEXT NOT NULL CHECK(status IN ('STARTED','SUCCEEDED','OUTCOME_UNKNOWN')),"
                "started_at TEXT NOT NULL, completed_at TEXT, error_class TEXT, result_hash TEXT)"
            )
        except sqlite3.Error as exc:
            raise CompletionJournalError(f"completion journal open failed:{type(exc).__name__}") from exc

    @property
    def durable(self) -> bool:
        return self.path != ":memory:"

    def close(self) -> None:
        self._conn.close()

    def _row(self, execution_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT execution_id,authorization_receipt_hash,action_hash,status,started_at,completed_at,error_class,result_hash "
            "FROM effect_completion WHERE execution_id=?",
            (execution_id,),
        ).fetchone()
        if row is None:
            return None
        keys = ("execution_id", "authorization_receipt_hash", "action_hash", "status", "started_at", "completed_at", "error_class", "result_hash")
        return dict(zip(keys, row))

    def begin(self, receipt_hash: str, action_hash: str, *, now: datetime | None = None) -> dict[str, Any]:
        receipt_hash = _require_hash(receipt_hash, "authorization_receipt_hash")
        action_hash = _require_hash(action_hash, "action_hash")
        execution_id = execution_id_for(receipt_hash, action_hash)
        try:
            self._conn.execute("BEGIN IMMEDIATE")
            existing = self._row(execution_id)
            if existing is None:
                self._conn.execute(
                    "INSERT INTO effect_completion(execution_id,authorization_receipt_hash,action_hash,status,started_at) VALUES(?,?,?,'STARTED',?)",
                    (execution_id, receipt_hash, action_hash, _utc_text(now)),
                )
                existing = self._row(execution_id)
            self._conn.execute("COMMIT")
            assert existing is not None
            return existing
        except sqlite3.Error as exc:
            try:
                self._conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise CompletionJournalError(f"completion begin failed:{type(exc).__name__}") from exc

    def finish(self, execution_id: str, status: str, *, result_hash: str | None = None, error_class: str | None = None, now: datetime | None = None) -> dict[str, Any]:
        _require_hash(execution_id, "execution_id")
        if status not in _FINAL_COMPLETION_STATES:
            raise CompletionJournalError("invalid final completion status")
        if result_hash is not None:
            _require_hash(result_hash, "result_hash")
        if error_class is not None and (not isinstance(error_class, str) or not error_class):
            raise CompletionJournalError("invalid error_class")
        try:
            self._conn.execute("BEGIN IMMEDIATE")
            existing = self._row(execution_id)
            if existing is None:
                raise CompletionJournalError("unknown execution_id")
            if existing["status"] == "STARTED":
                self._conn.execute(
                    "UPDATE effect_completion SET status=?,completed_at=?,error_class=?,result_hash=? WHERE execution_id=? AND status='STARTED'",
                    (status, _utc_text(now), error_class, result_hash, execution_id),
                )
            elif existing["status"] != status:
                raise CompletionJournalError("completion is already final")
            final = self._row(execution_id)
            self._conn.execute("COMMIT")
            assert final is not None
            return final
        except CompletionJournalError:
            try:
                self._conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        except sqlite3.Error as exc:
            try:
                self._conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise CompletionJournalError(f"completion finish failed:{type(exc).__name__}") from exc

    def get(self, execution_id: str) -> dict[str, Any] | None:
        _require_hash(execution_id, "execution_id")
        return self._row(execution_id)

    def effective_status(self, execution_id: str) -> str | None:
        row = self.get(execution_id)
        if row is None:
            return None
        return "OUTCOME_UNKNOWN" if row["status"] == "STARTED" else row["status"]


class PreparedAction:
    """Deeply immutable canonical adapter-resolved action."""

    __slots__ = ("_adapter_id", "_payload_json", "_action_hash", "_sealed")

    def __init__(self, *, adapter_id: str, broker_request: Mapping[str, Any], parameters: Any, cost: Mapping[str, int], security_effects: Mapping[str, Any] | None = None):
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
    def adapter_id(self) -> str: return self._adapter_id
    @property
    def broker_request(self) -> dict[str, Any]: return self._payload()["broker_request"]
    @property
    def parameters(self) -> Any: return self._payload()["parameters"]
    @property
    def cost(self) -> dict[str, int]: return self._payload()["cost"]
    @property
    def security_effects(self) -> dict[str, list[str]]: return self._payload()["security_effects"]
    def canonical_payload(self) -> dict[str, Any]: return self._payload()
    @property
    def action_hash(self) -> str: return self._action_hash


class TrustedAdapter(Protocol):
    adapter_id: str
    def prepare(self, request: Mapping[str, Any]) -> PreparedAction: ...
    def execute(self, action: PreparedAction) -> Any: ...


class AuthorizationBroker(Protocol):
    def authorize(self, request: dict[str, Any], *, cost: dict[str, int], now: datetime | None = None, execution_binding_hash: str | None = None) -> dict[str, Any]: ...


_REQUIRED_BROKER_FIELDS = {"request_id", "lease_id", "nonce", "sequence", "principal", "objective_id", "operation", "target", "side_effect", "timestamp"}
_BOUND_ENVELOPE_FIELDS = ("request_id", "lease_id", "nonce", "sequence", "principal", "objective_id", "timestamp")


class MediatedExecutor:
    """Prepare, authorize, journal, and execute one mediated action."""

    def __init__(self, broker: AuthorizationBroker, adapters: Mapping[str, TrustedAdapter], capability_contracts: Mapping[str, Mapping[str, Any]] | None = None, *, completion_journal: SQLiteCompletionJournal):
        if not adapters:
            raise ValueError("at least one trusted adapter is required")
        if not isinstance(completion_journal, SQLiteCompletionJournal):
            raise ValueError("a completion journal is required")
        self.broker = broker
        self.completion_journal = completion_journal
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
        action = PreparedAction(adapter_id=adapter_id, broker_request=broker_request, parameters=prepared.parameters, cost=prepared.cost, security_effects=prepared.security_effects)
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
        if now.tzinfo is None: now = now.replace(tzinfo=timezone.utc)
        else: now = now.astimezone(timezone.utc)
        try:
            prepared = self._prepare(request)
        except (ExecutionBindingError, CanonicalJSONError, TypeError, ValueError, RecursionError) as exc:
            return {"decision": "DENY", "reason": f"preparation_failed:{type(exc).__name__}", "executed": False, "completion_status": "NOT_STARTED", "execution_id": None, "action_hash": None, "authorization_receipt": None, "completion_record": None, "result": None}

        action_hash = prepared.action_hash
        receipt = self.broker.authorize(prepared.broker_request, cost=prepared.cost, now=now, execution_binding_hash=action_hash)
        if not isinstance(receipt, dict):
            raise ExecutionBindingError("authorization broker returned invalid receipt")
        if receipt.get("execution_binding_hash") != action_hash:
            return {"decision": "DENY", "reason": "authorization_binding_mismatch", "executed": False, "completion_status": "NOT_STARTED", "execution_id": None, "action_hash": action_hash, "authorization_receipt": copy.deepcopy(receipt), "completion_record": None, "result": None}
        authorization = copy.deepcopy(receipt)
        if receipt.get("decision") != "ALLOW":
            return {"decision": receipt.get("decision", "DENY"), "reason": receipt.get("reason", "authorization_failed"), "executed": False, "completion_status": "NOT_STARTED", "execution_id": None, "action_hash": action_hash, "authorization_receipt": authorization, "completion_record": None, "result": None}

        receipt_hash = receipt.get("receipt_hash")
        try:
            started = self.completion_journal.begin(receipt_hash, action_hash, now=now)
        except (CompletionJournalError, TypeError, ValueError) as exc:
            return {"decision": "DENY", "reason": f"completion_journal_failed:{type(exc).__name__}", "executed": False, "completion_status": "NOT_STARTED", "execution_id": None, "action_hash": action_hash, "authorization_receipt": authorization, "completion_record": None, "result": None}

        execution_id = started["execution_id"]
        if started["status"] != "STARTED":
            effective = self.completion_journal.effective_status(execution_id)
            return {"decision": "DENY", "reason": "execution_already_recorded", "executed": effective == "SUCCEEDED", "completion_status": effective, "execution_id": execution_id, "action_hash": action_hash, "authorization_receipt": authorization, "completion_record": started, "result": None}

        adapter = self._adapters[prepared.adapter_id]
        try:
            raw_result = adapter.execute(prepared)
        except BaseException as exc:
            try:
                completion = self.completion_journal.finish(execution_id, "OUTCOME_UNKNOWN", error_class=type(exc).__name__)
            except CompletionJournalError:
                completion = {**started, "status": "OUTCOME_UNKNOWN", "error_class": type(exc).__name__}
            return {"decision": "ALLOW", "reason": "authorized_dispatch_outcome_unknown", "executed": None, "completion_status": "OUTCOME_UNKNOWN", "execution_id": execution_id, "action_hash": action_hash, "authorization_receipt": authorization, "completion_record": completion, "result": None}

        result_error = None
        cloned_result = None
        result_hash = None
        try:
            cloned_result = _result_clone(raw_result)
            result_hash = _result_hash(cloned_result)
        except ExecutionBindingError as exc:
            result_error = type(exc).__name__

        try:
            completion = self.completion_journal.finish(execution_id, "SUCCEEDED", result_hash=result_hash, error_class=result_error)
        except CompletionJournalError as exc:
            return {"decision": "ALLOW", "reason": "authorized_dispatch_outcome_unknown", "executed": None, "completion_status": "OUTCOME_UNKNOWN", "execution_id": execution_id, "action_hash": action_hash, "authorization_receipt": authorization, "completion_record": {**started, "status": "OUTCOME_UNKNOWN", "error_class": type(exc).__name__}, "result": None}

        return {"decision": "ALLOW", "reason": "authorized_and_executed" if result_error is None else "authorized_and_executed_result_unavailable", "executed": True, "completion_status": "SUCCEEDED", "execution_id": execution_id, "action_hash": action_hash, "authorization_receipt": authorization, "completion_record": completion, "result": cloned_result}
