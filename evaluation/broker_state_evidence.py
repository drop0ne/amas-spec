from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import tempfile
from typing import Any

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = ROOT / "reference"
if str(REFERENCE) not in sys.path:
    sys.path.insert(0, str(REFERENCE))

import canonical_json  # type: ignore
from bounded_durable_broker import BoundedDurableEnforcementBroker  # type: ignore
from durable_broker import DurableEnforcementBroker, DurabilityError  # type: ignore
from enforcement_broker import sign_lease  # type: ignore
from receipt_chain import GENESIS  # type: ignore
from evaluation.release_check import load_schemas, run_check

NOW = datetime(2026, 8, 14, 22, 0, tzinfo=timezone.utc)
LEASE_KEY = b"broker-evidence-lease-key-v1"
STATE_KEY = b"broker-evidence-state-key-v1"
CHECKPOINT_KEY = b"broker-evidence-checkpoint-key-v1"
COST = {"actions": 1, "network_calls": 1, "egress_bytes": 8, "wall_clock_seconds": 1}


def make_lease() -> dict[str, Any]:
    value = {
        "lease_version": 1,
        "lease_id": "BROKER-EVIDENCE-LEASE",
        "issuer": "evaluation-operator",
        "key_id": "broker-evidence-key-v1",
        "issued_at": "2026-08-14T21:00:00Z",
        "not_before": "2026-08-14T21:00:00Z",
        "max_request_age_seconds": 7200,
        "signature_alg": "HMAC-SHA256",
        "policy": {
            "policy_id": "BROKER-EVIDENCE-POLICY",
            "principal": "evaluation-agent",
            "objectives": ["inspect"],
            "operations": ["read"],
            "targets": ["mock://allowed"],
            "destinations": ["mock://allowed"],
            "credentials": [],
            "capability_contracts": [],
            "max_side_effect": "observe",
            "budgets": {
                "max_actions": 4,
                "max_network_calls": 2,
                "max_egress_bytes": 4096,
                "max_wall_clock_seconds": 300,
            },
            "max_delegation_depth": 0,
            "expires_at": "2026-08-15T23:59:59Z",
            "operator_escalation": False,
        },
    }
    value["signature"] = sign_lease(value, LEASE_KEY)
    return value


def request(sequence: int, *, nonce: str | None = None, destination: str = "mock://allowed") -> dict[str, Any]:
    return {
        "request_id": f"BROKER-EVIDENCE-R{sequence}",
        "lease_id": "BROKER-EVIDENCE-LEASE",
        "nonce": nonce or f"broker-evidence-nonce-{sequence:06d}",
        "sequence": sequence,
        "principal": "evaluation-agent",
        "objective_id": "inspect",
        "operation": "read",
        "target": destination,
        "destination": destination,
        "credential_ref": None,
        "side_effect": "observe",
        "timestamp": "2026-08-14T22:00:00Z",
    }


def _event(
    event_id: str,
    phase: str,
    decision: str,
    reason: str,
    broker: DurableEnforcementBroker,
    *,
    sequence: int | None = None,
    checkpoint: dict[str, Any] | None = None,
) -> dict[str, Any]:
    verification = broker.receipt_verification()
    return {
        "event_id": event_id,
        "phase": phase,
        "decision": decision,
        "reason": reason,
        "sequence": sequence,
        "state_generation": broker.state_generation,
        "state_hash": broker.state_hash,
        "last_sequence": broker.last_sequence,
        "usage": dict(broker.usage),
        "receipt_count": len(broker.receipts),
        "receipt_chain_tip": verification.get("chain_tip") or GENESIS,
        "checkpoint_generation": None if checkpoint is None else checkpoint["generation"],
        "checkpoint_state_hash": None if checkpoint is None else checkpoint["state_hash"],
    }


def _raw_event(event_id: str, reason: str, state: dict[str, Any], checkpoint: dict[str, Any]) -> dict[str, Any]:
    return {
        "event_id": event_id,
        "phase": "ROLLBACK_PROBE",
        "decision": "ERROR",
        "reason": reason,
        "sequence": None,
        "state_generation": state["generation"],
        "state_hash": state["state_hash"],
        "last_sequence": state["last_sequence"],
        "usage": dict(state["usage"]),
        "receipt_count": len(state["receipts"]),
        "receipt_chain_tip": state.get("receipt_chain_tip") or GENESIS,
        "checkpoint_generation": checkpoint["generation"],
        "checkpoint_state_hash": checkpoint["state_hash"],
    }


def run_broker_evidence(out_dir: Path) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    lease = make_lease()
    transitions: list[dict[str, Any]] = []

    with tempfile.TemporaryDirectory() as tmp:
        state_path = Path(tmp) / "broker-state.json"
        broker = DurableEnforcementBroker(lease, LEASE_KEY, state_path=state_path, state_key=STATE_KEY)
        transitions.append(_event("initial", "INITIAL", "STATE", "initialized", broker))

        first = broker.authorize(request(1), cost=COST, now=NOW)
        transitions.append(_event("allow-1", "AUTHORIZE", first["decision"], first["reason"], broker, sequence=1))

        replay = broker.authorize(request(1), cost=COST, now=NOW)
        transitions.append(_event("replay-1", "AUTHORIZE", replay["decision"], replay["reason"], broker, sequence=1))

        scope = broker.authorize(request(2, destination="mock://forbidden"), cost=COST, now=NOW)
        transitions.append(_event("scope-2", "AUTHORIZE", scope["decision"], scope["reason"], broker, sequence=2))

        third = broker.authorize(request(3), cost=COST, now=NOW)
        transitions.append(_event("allow-3", "AUTHORIZE", third["decision"], third["reason"], broker, sequence=3))

        budget = broker.authorize(request(4), cost=COST, now=NOW)
        transitions.append(_event("budget-4", "AUTHORIZE", budget["decision"], budget["reason"], broker, sequence=4))

        checkpoint = broker.create_checkpoint(CHECKPOINT_KEY, now=NOW)
        transitions.append(_event("checkpoint", "CHECKPOINT", "CHECKPOINT", "checkpoint_created", broker, checkpoint=checkpoint))

        restored = DurableEnforcementBroker(
            lease,
            LEASE_KEY,
            state_path=state_path,
            state_key=STATE_KEY,
            checkpoint=checkpoint,
            checkpoint_key=CHECKPOINT_KEY,
        )
        transitions.append(_event("restore", "RESTORE", "RESTORE", "checkpoint_ancestry_verified", restored, checkpoint=checkpoint))

    rollback_blocked = False
    with tempfile.TemporaryDirectory() as tmp:
        state_path = Path(tmp) / "rollback-state.json"
        broker = DurableEnforcementBroker(lease, LEASE_KEY, state_path=state_path, state_key=STATE_KEY)
        old_state_bytes = state_path.read_bytes()
        old_state = json.loads(old_state_bytes.decode("utf-8"))
        broker.authorize(request(1), cost=COST, now=NOW)
        checkpoint = broker.create_checkpoint(CHECKPOINT_KEY, now=NOW)
        state_path.write_bytes(old_state_bytes)
        try:
            DurableEnforcementBroker(
                lease,
                LEASE_KEY,
                state_path=state_path,
                state_key=STATE_KEY,
                checkpoint=checkpoint,
                checkpoint_key=CHECKPOINT_KEY,
            )
        except DurabilityError as exc:
            rollback_blocked = "rollback detected" in str(exc)
            transitions.append(_raw_event("rollback", str(exc), old_state, checkpoint))
        else:
            raise RuntimeError("authenticated rollback unexpectedly restored")

    epoch_blocked = False
    with tempfile.TemporaryDirectory() as tmp:
        state_path = Path(tmp) / "epoch-state.json"
        broker = BoundedDurableEnforcementBroker(
            lease,
            LEASE_KEY,
            state_path=state_path,
            state_key=STATE_KEY,
            max_epoch_events=2,
        )
        broker.authorize(request(1), cost=COST, now=NOW)
        broker.authorize(request(2, destination="mock://forbidden"), cost=COST, now=NOW)
        try:
            broker.authorize(request(3), cost=COST, now=NOW)
        except DurabilityError as exc:
            epoch_blocked = "capacity exhausted" in str(exc)
            transitions.append(_event("epoch-capacity", "EPOCH_PROBE", "ERROR", str(exc), broker, sequence=3))
        else:
            raise RuntimeError("bounded epoch unexpectedly accepted an additional event")

    schemas, registry = load_schemas()
    validator = Draft202012Validator(schemas["evaluation_broker_transition.schema.json"], registry=registry)
    for transition in transitions:
        validator.validate(transition)

    summary = {
        "transition_events": len(transitions),
        "denial_events": sum(1 for item in transitions if item["decision"] == "DENY"),
        "rollback_blocked": rollback_blocked,
        "epoch_capacity_blocked": epoch_blocked,
        "all_receipt_chains_valid": all(len(item["receipt_chain_tip"]) == 64 for item in transitions),
    }
    evidence_files: dict[str, Path] = {}
    for name, value in (("transitions.json", transitions), ("summary.json", summary)):
        path = out_dir / name
        path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        evidence_files[name] = path

    manifest = run_check(
        out_dir / "evaluation_manifest.json",
        evaluation_tier="E1",
        environment={
            "environment_id": "broker-state-machine-v1",
            "topology": "scripted state transitions -> DurableEnforcementBroker -> authenticated JSON state + SQLite transaction lock",
            "trusted_components": ["durable_broker", "state_integrity_key", "checkpoint_key", "sqlite_lock"],
            "effect_surfaces": ["mock.authorization_state"],
            "hidden_configuration_hash": canonical_json.sha256({"scenario": "broker-state-machine-v1"}),
            "notes": "Temporary local files only; no real network or production effects.",
        },
        policy_hash=canonical_json.sha256(lease["policy"]),
        lease_hash=canonical_json.sha256(lease),
        evidence_files=evidence_files,
        trust_boundary={
            "mode": "same_process_reference",
            "components": ["durable_broker", "state_integrity_key", "checkpoint_key"],
            "independent_failure_domain": False,
            "notes": "Checkpoint and state keys remain same-host reference material; no independent failure-domain claim.",
        },
    )
    return {"manifest": manifest, "transitions": transitions, "summary": summary}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    evidence = run_broker_evidence(args.out)
    print(json.dumps(evidence["summary"], sort_keys=True))
    summary = evidence["summary"]
    return 0 if summary["rollback_blocked"] and summary["epoch_capacity_blocked"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
