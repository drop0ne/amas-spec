from __future__ import annotations

import copy
from hashlib import sha256
import json
from pathlib import Path
import sys
from typing import Any, Mapping, Protocol

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]
REFERENCE = ROOT / "reference"
if str(REFERENCE) not in sys.path:
    sys.path.insert(0, str(REFERENCE))

import canonical_json  # type: ignore
from evaluation.mediated_agent.aab_harness import AABEvaluationHarness, CAP_ID


class ProviderContractError(RuntimeError):
    pass


class ProviderUnavailable(ProviderContractError):
    pass


class ModelProvider(Protocol):
    provider_id: str
    model_id: str
    model_version: str

    def propose(self, task: Mapping[str, Any]) -> Mapping[str, Any]: ...


def _require_identity(value: str, name: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 256:
        raise ValueError(f"invalid {name}")
    return value


def _security_clone(value: Any) -> Any:
    try:
        return json.loads(canonical_json.dumps(value))
    except Exception as exc:
        raise ProviderContractError("value is not Canonical JSON v1") from exc


class TrustedProposalBinder:
    """Bind untrusted provider proposals to trusted evaluation authority identity.

    The provider may choose requested operation/target/destination/credential,
    side-effect class, and tool parameters. It cannot provide or override the
    adapter, lease, principal, objective, nonce, sequence, timestamp, request
    identity, usage accounting, or capability-contract identity.
    """

    def __init__(
        self,
        *,
        adapter_id: str = "eval_mock",
        lease_id: str = "EVAL-LEASE-1",
        principal: str = "evaluation-agent",
        objective_id: str = "inspect",
        capability_contract_id: str = CAP_ID,
        timestamp: str = "2026-08-14T21:30:00Z",
        nonce_salt: str = "e2-provider-binder-v1",
    ) -> None:
        self.adapter_id = _require_identity(adapter_id, "adapter_id")
        self.lease_id = _require_identity(lease_id, "lease_id")
        self.principal = _require_identity(principal, "principal")
        self.objective_id = _require_identity(objective_id, "objective_id")
        self.capability_contract_id = _require_identity(capability_contract_id, "capability_contract_id")
        self.timestamp = _require_identity(timestamp, "timestamp")
        self.nonce_salt = _require_identity(nonce_salt, "nonce_salt")
        schema = json.loads((ROOT / "evaluation" / "schemas" / "evaluation_model_proposal.schema.json").read_text(encoding="utf-8"))
        self._validator = Draft202012Validator(schema)
        self._sequence = 0

    @property
    def sequence(self) -> int:
        return self._sequence

    def bind(self, task_id: str, proposal: Mapping[str, Any]) -> dict[str, Any]:
        task_id = _require_identity(task_id, "task_id")
        if not isinstance(proposal, Mapping):
            raise ProviderContractError("provider proposal must be an object")
        cloned = _security_clone(dict(proposal))
        errors = sorted(self._validator.iter_errors(cloned), key=lambda item: list(item.path))
        if errors:
            raise ProviderContractError(f"provider proposal schema violation:{errors[0].message}")

        sequence = self._sequence + 1
        nonce_material = f"{self.nonce_salt}\x00{task_id}\x00{sequence}".encode("utf-8")
        nonce = sha256(nonce_material).hexdigest()
        request = {
            "adapter_id": self.adapter_id,
            "request_id": f"E2-{sequence:06d}-{task_id}",
            "lease_id": self.lease_id,
            "nonce": nonce,
            "sequence": sequence,
            "principal": self.principal,
            "objective_id": self.objective_id,
            "operation": cloned["operation"],
            "target": cloned["target"],
            "destination": cloned["destination"],
            "credential_ref": cloned["credential_ref"],
            "side_effect": cloned["side_effect"],
            "timestamp": self.timestamp,
            "parameters": cloned["parameters"],
            "capability_contract_id": self.capability_contract_id,
        }
        canonical_json.validate(request)
        self._sequence = sequence
        return request


class ScriptedProvider:
    """Deterministic no-network provider used only to test the E2 interface contract."""

    provider_id = "offline-scripted-provider"
    model_id = "scripted-fixture"
    model_version = "1"

    def __init__(self, proposals: Mapping[str, Any]) -> None:
        self._proposals = copy.deepcopy(dict(proposals))

    def propose(self, task: Mapping[str, Any]) -> Mapping[str, Any]:
        task_id = task.get("task_id") if isinstance(task, Mapping) else None
        if not isinstance(task_id, str) or task_id not in self._proposals:
            raise ProviderUnavailable("scripted response unavailable")
        value = self._proposals[task_id]
        if isinstance(value, BaseException):
            raise value
        return copy.deepcopy(value)


class ProviderEvaluationHarness:
    """Provider-control-plane contract feeding the existing AAB evaluation path."""

    def __init__(self, provider: ModelProvider, *, binder: TrustedProposalBinder | None = None) -> None:
        self.provider = provider
        self.provider_id = _require_identity(provider.provider_id, "provider_id")
        self.model_id = _require_identity(provider.model_id, "model_id")
        self.model_version = _require_identity(provider.model_version, "model_version")
        self.binder = binder or TrustedProposalBinder()
        self.aab = AABEvaluationHarness()

    def evaluate(self, task: Mapping[str, Any]) -> dict[str, Any]:
        if not isinstance(task, Mapping):
            raise ProviderContractError("task must be an object")
        task_copy = _security_clone(dict(task))
        task_id = task_copy.get("task_id")
        prompt = task_copy.get("prompt")
        if not isinstance(task_id, str) or not task_id or not isinstance(prompt, str) or not prompt:
            raise ProviderContractError("task requires non-empty task_id and prompt")
        if set(task_copy) != {"task_id", "prompt"}:
            raise ProviderContractError("task contains unknown control-plane fields")

        before = len(self.aab.adapter.events())
        task_hash = canonical_json.sha256(task_copy)
        try:
            raw_proposal = self.provider.propose(copy.deepcopy(task_copy))
            proposal = _security_clone(dict(raw_proposal)) if isinstance(raw_proposal, Mapping) else raw_proposal
            request = self.binder.bind(task_id, proposal)
        except (ProviderContractError, ProviderUnavailable, TypeError, ValueError, KeyError, RuntimeError) as exc:
            return {
                "decision": "DENY",
                "reason": f"provider_or_binding_failed:{type(exc).__name__}",
                "effect_delta": len(self.aab.adapter.events()) - before,
                "provider": self.provider_id,
                "model": self.model_id,
                "model_version": self.model_version,
                "task_hash": task_hash,
                "proposal_hash": None,
                "aab_result": None,
            }

        proposal_hash = canonical_json.sha256(proposal)
        result = self.aab.execute(request)
        return {
            "decision": result.get("decision", "DENY"),
            "reason": result.get("reason", "authorization_failed"),
            "effect_delta": len(self.aab.adapter.events()) - before,
            "provider": self.provider_id,
            "model": self.model_id,
            "model_version": self.model_version,
            "task_hash": task_hash,
            "proposal_hash": proposal_hash,
            "aab_result": result,
        }

    def close(self) -> None:
        self.aab.close()

    def __enter__(self) -> "ProviderEvaluationHarness":
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()
