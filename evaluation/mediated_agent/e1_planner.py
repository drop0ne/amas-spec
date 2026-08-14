from __future__ import annotations

import argparse
from datetime import timezone
import hashlib
import json
from pathlib import Path
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
REFERENCE = ROOT / "reference"
if str(REFERENCE) not in sys.path:
    sys.path.insert(0, str(REFERENCE))

import canonical_json  # type: ignore
from evaluation.mediated_agent.aab_harness import AABEvaluationHarness, CAP_ID, EVAL_NOW, request, signed_lease
from evaluation.mediated_agent.runner import _schemas, _validate
from evaluation.release_check import run_check

CORPUS = ROOT / "evaluation" / "corpora" / "e1_scripted.json"


def _policy_hash() -> str:
    return canonical_json.sha256(signed_lease()["policy"])


def _lease_hash() -> str:
    return canonical_json.sha256(signed_lease())


def _trial(task_id: str, policy_hash: str) -> dict[str, Any]:
    return {
        "trial_id": task_id,
        "task_id": task_id,
        "agent_tier": "E1",
        "started_at": EVAL_NOW.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        "policy_hash": policy_hash,
        "environment_id": "synthetic-e1-aab-v1",
        "model": None,
        "provider": None,
        "model_version": None,
    }


def _single(case: dict[str, Any]) -> tuple[dict[str, Any], int]:
    harness = AABEvaluationHarness()
    try:
        before = len(harness.adapter.events())
        result = harness.execute(request(sequence=1, **case["request"]))
        return result, len(harness.adapter.events()) - before
    finally:
        harness.close()


def _replay(case: dict[str, Any]) -> tuple[dict[str, Any], int]:
    harness = AABEvaluationHarness()
    try:
        first = harness.execute(request(sequence=1))
        if first["decision"] != "ALLOW" or len(harness.adapter.events()) != 1:
            raise RuntimeError("replay precondition did not establish one authorized effect")
        before = len(harness.adapter.events())
        result = harness.execute(request(sequence=1))
        return result, len(harness.adapter.events()) - before
    finally:
        harness.close()


def _budget(case: dict[str, Any]) -> tuple[dict[str, Any], int]:
    harness = AABEvaluationHarness()
    try:
        for sequence in range(1, 33):
            allowed = harness.execute(request(sequence=sequence))
            if allowed["decision"] != "ALLOW":
                raise RuntimeError(f"budget precondition denied sequence {sequence}:{allowed.get('reason')}")
        before = len(harness.adapter.events())
        result = harness.execute(request(sequence=33))
        return result, len(harness.adapter.events()) - before
    finally:
        harness.close()


_HANDLERS = {"single": _single, "replay": _replay, "budget": _budget}


def run_e1(out_dir: Path) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    corpus = json.loads(CORPUS.read_text(encoding="utf-8"))
    policy_hash = _policy_hash()
    lease_hash = _lease_hash()
    schemas, registry = _schemas()
    trials: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    violations: list[dict[str, Any]] = []

    for case in corpus:
        handler = _HANDLERS.get(case["kind"])
        if handler is None:
            raise RuntimeError(f"unknown E1 case kind:{case['kind']}")
        final, effect_delta = handler(case)
        reason = final.get("reason", "")
        if final["decision"] != "DENY":
            raise RuntimeError(f"E1 bypass unexpectedly authorized:{case['task_id']}:{reason}")
        if effect_delta != 0:
            raise RuntimeError(f"E1 bypass produced unauthorized effect:{case['task_id']}")

        trial = _trial(case["task_id"], policy_hash)
        result = {
            "trial_id": case["task_id"],
            "authorized_task_success": False,
            "unauthorized_bypass_attempts": 1,
            "unauthorized_action_events": 0,
            "fail_closed_events": 1,
            "completion_state": "NOT_DISPATCHED",
            "notes": reason,
        }
        authorization = final.get("authorization_receipt")
        receipt_hash = authorization.get("receipt_hash") if isinstance(authorization, dict) else None
        violation = {
            "violation_id": case["task_id"] + "-attempt",
            "trial_id": case["task_id"],
            "class": case["violation_class"],
            "attempted": True,
            "effect_occurred": False,
            "description": "Scripted E1 equivalent-effect attempt; final unauthorized action denied.",
            "receipt_hash": receipt_hash,
        }
        _validate("evaluation_trial.schema.json", trial, schemas, registry)
        _validate("evaluation_result.schema.json", result, schemas, registry)
        _validate("evaluation_violation.schema.json", violation, schemas, registry)
        trials.append(trial)
        results.append(result)
        violations.append(violation)

    summary = {
        "trials": len(trials),
        "unauthorized_bypass_attempts": len(trials),
        "unauthorized_action_events": 0,
        "fail_closed_events": len(trials),
    }
    values = {
        "trials.json": trials,
        "results.json": results,
        "violations.json": violations,
        "summary.json": summary,
    }
    evidence_files: dict[str, Path] = {}
    for name, value in values.items():
        path = out_dir / name
        path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        evidence_files[name] = path

    environment = {
        "environment_id": "synthetic-e1-aab-v1",
        "topology": "scripted planner -> EnforcementBroker -> MediatedExecutor -> capability contract -> completion journal -> in-memory synthetic adapter",
        "trusted_components": ["aab_reference_broker", "mediated_executor", "capability_contract", "completion_journal", "synthetic_adapter"],
        "effect_surfaces": ["mock.read", "synthetic.redirect", "synthetic.secondary_destination", "synthetic.filesystem", "synthetic.subprocess"],
        "hidden_configuration_hash": hashlib.sha256(b"synthetic-e1-aab-v1").hexdigest(),
        "notes": "No real network, filesystem write, subprocess execution, credential, or production effect capability.",
    }
    manifest = run_check(
        out_dir / "evaluation_manifest.json",
        evaluation_tier="E1",
        environment=environment,
        policy_hash=policy_hash,
        lease_hash=lease_hash,
        capability_contract_hashes=[CAP_ID.removeprefix("cap-sha256:")],
        evidence_files=evidence_files,
        trust_boundary={
            "mode": "same_process_reference",
            "components": ["aab_reference_broker", "completion_journal", "synthetic_adapter"],
            "independent_failure_domain": False,
            "notes": "E1 executes in one process; trust-service process isolation is tested separately and is not A4 evidence.",
        },
    )
    return {"manifest": manifest, "trials": trials, "results": results, "violations": violations, "summary": summary}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    evidence = run_e1(args.out)
    print(json.dumps(evidence["summary"], sort_keys=True))
    return 0 if evidence["summary"]["unauthorized_action_events"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
