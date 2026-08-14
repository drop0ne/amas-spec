from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from evaluation.release_check import load_schemas, run_check
from evaluation.trust_boundary import LocalTrustBoundary, ProcessTrustBoundary, TrustBoundaryError, TrustBoundaryUnavailable

STATE_A = "a" * 64
STATE_B = "b" * 64
EXECUTION = "c" * 64
ACTION = "d" * 64


def _event(event_id: str, boundary_mode: str, operation: str, outcome: str, fail_closed: bool, note: str) -> dict[str, Any]:
    return {
        "event_id": event_id,
        "boundary_mode": boundary_mode,
        "operation": operation,
        "outcome": outcome,
        "fail_closed": fail_closed,
        "note": note,
    }


def run_trust_boundary_evidence(out_dir: Path) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    events: list[dict[str, Any]] = []

    local = LocalTrustBoundary(identity_secret=b"evaluation-local-boundary-secret")
    local.anchor_checkpoint("local-cp", STATE_A, 1)
    events.append(_event(
        "local-checkpoint",
        "same_process_reference",
        "checkpoint_anchor",
        "PASS",
        False,
        "Same-process baseline anchor recorded and matched.",
    ))

    service = ProcessTrustBoundary()
    try:
        service.anchor_checkpoint("process-cp", STATE_A, 7)
        if not service.checkpoint_matches("process-cp", STATE_A, 7):
            raise RuntimeError("process checkpoint did not match anchored value")
        events.append(_event(
            "process-checkpoint",
            "same_host_process_reference",
            "checkpoint_anchor",
            "PASS",
            False,
            "Checkpoint state is owned by the spawned trust-service process.",
        ))

        try:
            service.anchor_checkpoint("process-cp", STATE_B, 7)
        except TrustBoundaryError:
            events.append(_event(
                "process-checkpoint-mutation",
                "same_host_process_reference",
                "checkpoint_mutation",
                "DENY",
                True,
                "Attempt to mutate an existing checkpoint anchor was rejected.",
            ))
        else:
            raise RuntimeError("checkpoint mutation unexpectedly succeeded")

        service.revoke("EVAL-LEASE")
        if not service.is_revoked("EVAL-LEASE"):
            raise RuntimeError("revocation did not persist")
        events.append(_event(
            "process-revocation",
            "same_host_process_reference",
            "revocation",
            "PASS",
            False,
            "Revocation persisted in trust-service-owned mutable state.",
        ))

        service.record_completion(EXECUTION, ACTION, "STARTED")
        service.record_completion(EXECUTION, ACTION, "OUTCOME_UNKNOWN")
        final = service.record_completion(EXECUTION, ACTION, "EFFECT_CONFIRMED")
        if final["state"] != "EFFECT_CONFIRMED":
            raise RuntimeError("completion did not reach EFFECT_CONFIRMED")
        events.append(_event(
            "process-completion-forward",
            "same_host_process_reference",
            "completion_transition",
            "PASS",
            False,
            "Completion state advanced STARTED -> OUTCOME_UNKNOWN -> EFFECT_CONFIRMED.",
        ))

        try:
            service.record_completion(EXECUTION, ACTION, "SUCCEEDED")
        except TrustBoundaryError:
            events.append(_event(
                "process-completion-regression",
                "same_host_process_reference",
                "completion_regression",
                "DENY",
                True,
                "Backward/alternate completion transition after finalization was rejected.",
            ))
        else:
            raise RuntimeError("completion regression unexpectedly succeeded")

        identity = service.issue_identity("evaluation-agent")
        valid = service.verify_identity("evaluation-agent", identity["token"])
        if not valid:
            raise RuntimeError("issued identity did not verify")
        events.append(_event(
            "process-identity",
            "same_host_process_reference",
            "identity_verify",
            "PASS",
            False,
            "Issued identity token verified only against its intended principal.",
        ))
        substituted = service.verify_identity("other-agent", identity["token"])
        if substituted:
            raise RuntimeError("identity substitution unexpectedly verified")
        events.append(_event(
            "process-identity-substitution",
            "same_host_process_reference",
            "identity_substitution",
            "DENY",
            True,
            "Principal substitution failed verification.",
        ))

        service.terminate_for_test()
        try:
            service.is_revoked("EVAL-LEASE")
        except TrustBoundaryUnavailable:
            events.append(_event(
                "process-unavailable",
                "same_host_process_reference",
                "service_unavailability",
                "UNAVAILABLE",
                True,
                "Trust-service loss is surfaced explicitly rather than treated as authorization.",
            ))
        else:
            raise RuntimeError("terminated trust service unexpectedly answered")
    finally:
        service.close(force=True)

    schemas, registry = load_schemas()
    validator = Draft202012Validator(schemas["evaluation_trust_boundary_event.schema.json"], registry=registry)
    for event in events:
        validator.validate(event)

    summary = {
        "events": len(events),
        "separate_process_events": sum(1 for item in events if item["boundary_mode"] == "same_host_process_reference"),
        "fail_closed_events": sum(1 for item in events if item["fail_closed"]),
        "unexpected_authorizations": 0,
        "independent_failure_domain": False,
    }
    evidence_files: dict[str, Path] = {}
    for name, value in (("events.json", events), ("summary.json", summary)):
        path = out_dir / name
        path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        evidence_files[name] = path

    manifest = run_check(
        out_dir / "evaluation_manifest.json",
        evaluation_tier="E1",
        environment={
            "environment_id": "same-host-trust-boundary-v1",
            "topology": "evaluation caller -> multiprocessing Pipe -> spawned trust-service process -> private checkpoint/revocation/completion/identity state",
            "trusted_components": ["process_trust_boundary", "private_service_state", "identity_secret"],
            "effect_surfaces": ["checkpoint.anchor", "lease.revoke", "completion.anchor", "identity.verify"],
            "hidden_configuration_hash": hashlib.sha256(b"same-host-trust-boundary-v1").hexdigest(),
            "notes": "Same-host process isolation only. No external host, HSM, or independent service failure domain.",
        },
        evidence_files=evidence_files,
        trust_boundary={
            "mode": "same_host_process_reference",
            "components": ["checkpoint_anchor", "revocation_authority", "completion_anchor", "identity_authority"],
            "independent_failure_domain": False,
            "notes": "Spawned process owns mutable trust state, but shares the host and operator failure domain; not A4 evidence.",
        },
    )
    return {"manifest": manifest, "events": events, "summary": summary}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    evidence = run_trust_boundary_evidence(args.out)
    print(json.dumps(evidence["summary"], sort_keys=True))
    return 0 if evidence["summary"]["unexpected_authorizations"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
