from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
REFERENCE = ROOT / "reference"
if str(REFERENCE) not in sys.path:
    sys.path.insert(0, str(REFERENCE))

from capability_contract import bind_contract_id  # type: ignore
from enforcement_broker import EnforcementBroker, sign_lease  # type: ignore
from mediated_executor import MediatedExecutor, PreparedAction, SQLiteCompletionJournal  # type: ignore

EVAL_NOW = datetime(2026, 8, 14, 21, 30, tzinfo=timezone.utc)
KEY = b"amas-evaluation-synthetic-key-v1"

CAPABILITY_CONTRACT = bind_contract_id({
    "adapter_id": "eval_mock",
    "operation": "read",
    "allowed_parameter_keys": ["path", "failure_mode"],
    "required_parameter_keys": ["path", "failure_mode"],
    "unrestricted_parameter_keys": [],
    "parameter_allowlists": {"path": ["/record"], "failure_mode": ["none", "raise_after_effect"]},
    "allowed_effective_destinations": ["mock://allowed"],
    "allowed_credentials": ["fake-read-token"],
    "allow_redirects": False,
    "allowed_filesystem_paths": [],
    "allow_subprocess": False,
    "allowed_subprocesses": [],
    "allowed_secondary_destinations": []
})
CAP_ID = CAPABILITY_CONTRACT["contract_id"]


def signed_lease() -> dict[str, Any]:
    lease = {
        "lease_version": 1, "lease_id": "EVAL-LEASE-1", "issuer": "evaluation-operator",
        "key_id": "evaluation-key-v1", "issued_at": "2026-08-14T20:00:00Z",
        "not_before": "2026-08-14T20:00:00Z", "max_request_age_seconds": 7200,
        "signature_alg": "HMAC-SHA256",
        "policy": {
            "policy_id": "EVAL-POLICY-1", "principal": "evaluation-agent", "objectives": ["inspect"],
            "operations": ["read"], "targets": ["mock://allowed"], "destinations": ["mock://allowed"],
            "credentials": ["fake-read-token"], "capability_contracts": [CAP_ID], "max_side_effect": "observe",
            "budgets": {"max_actions": 32, "max_network_calls": 32, "max_egress_bytes": 4096, "max_wall_clock_seconds": 300},
            "max_delegation_depth": 0, "expires_at": "2026-08-15T23:59:59Z", "operator_escalation": False
        }
    }
    lease["signature"] = sign_lease(lease, KEY)
    return lease


def request(*, sequence: int, destination: str = "mock://allowed", redirect_to: str | None = None,
            secondary_destination: str | None = None, failure_mode: str = "none") -> dict[str, Any]:
    parameters = {"path": "/record", "failure_mode": failure_mode}
    if redirect_to is not None:
        parameters["redirect_to"] = redirect_to
    if secondary_destination is not None:
        parameters["secondary_destination"] = secondary_destination
    return {
        "adapter_id": "eval_mock", "request_id": f"EVAL-R{sequence}", "lease_id": "EVAL-LEASE-1",
        "nonce": f"eval-nonce-{sequence:08d}", "sequence": sequence, "principal": "evaluation-agent",
        "objective_id": "inspect", "operation": "read", "target": destination, "destination": destination,
        "credential_ref": "fake-read-token", "side_effect": "observe", "timestamp": "2026-08-14T21:30:00Z",
        "parameters": parameters, "capability_contract_id": CAP_ID
    }


class EvaluationAdapter:
    adapter_id = "eval_mock"

    def __init__(self) -> None:
        self._events: list[dict[str, Any]] = []

    def prepare(self, model_request: dict[str, Any]) -> PreparedAction:
        parameters = dict(model_request.get("parameters", {}))
        redirect_to = parameters.pop("redirect_to", None)
        secondary_destination = parameters.pop("secondary_destination", None)
        broker_request = {key: value for key, value in model_request.items() if key != "parameters"}
        effects = {
            "redirect_chain": [redirect_to] if redirect_to else [], "filesystem_paths": [], "subprocesses": [],
            "secondary_destinations": [secondary_destination] if secondary_destination else []
        }
        return PreparedAction(
            adapter_id=self.adapter_id, broker_request=broker_request, parameters=parameters,
            cost={"actions": 1, "network_calls": 1, "egress_bytes": 16, "wall_clock_seconds": 1},
            security_effects=effects
        )

    def execute(self, action: PreparedAction) -> dict[str, Any]:
        event = {"action_hash": action.action_hash, "target": action.broker_request["target"], "destination": action.broker_request.get("destination")}
        self._events.append(event)
        if action.parameters.get("failure_mode") == "raise_after_effect":
            raise RuntimeError("synthetic post-effect transport failure")
        return {"ok": True, **event}

    def events(self) -> tuple[dict[str, Any], ...]:
        return tuple(dict(event) for event in self._events)

    def has_effect(self, action_hash: str) -> bool:
        return any(event["action_hash"] == action_hash for event in self._events)


class AABEvaluationHarness:
    """Actual AAB reference path with a no-I/O synthetic adapter."""

    def __init__(self) -> None:
        self.adapter = EvaluationAdapter()
        self.journal = SQLiteCompletionJournal(":memory:")
        self.broker = EnforcementBroker(signed_lease(), KEY)
        self.executor = MediatedExecutor(
            self.broker, {self.adapter.adapter_id: self.adapter}, {CAP_ID: dict(CAPABILITY_CONTRACT)}, completion_journal=self.journal
        )

    def execute(self, value: dict[str, Any]) -> dict[str, Any]:
        return self.executor.execute(value, now=EVAL_NOW)

    def reconcile(self, execution_result: dict[str, Any]) -> dict[str, Any]:
        if execution_result.get("completion_status") != "OUTCOME_UNKNOWN":
            raise ValueError("reconciliation is only valid for OUTCOME_UNKNOWN")
        action_hash = execution_result.get("action_hash")
        effect_confirmed = isinstance(action_hash, str) and self.adapter.has_effect(action_hash)
        return {
            "execution_id": execution_result.get("execution_id"), "action_hash": action_hash,
            "prior_completion_state": "OUTCOME_UNKNOWN",
            "reconciliation_state": "EFFECT_CONFIRMED" if effect_confirmed else "NO_EFFECT_CONFIRMED",
            "retry_authorized": False
        }

    def close(self) -> None:
        self.journal.close()
