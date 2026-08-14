from pathlib import Path
import tempfile
import unittest

from evaluation.broker_state_evidence import run_broker_evidence
from evaluation.trust_boundary_evidence import run_trust_boundary_evidence


class EvaluationEvidenceRunnerTests(unittest.TestCase):
    def test_broker_state_runner_emits_manifest_bound_fail_closed_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            evidence = run_broker_evidence(out)
            summary = evidence["summary"]
            manifest = evidence["manifest"]
            self.assertTrue(summary["rollback_blocked"])
            self.assertTrue(summary["epoch_capacity_blocked"])
            self.assertGreaterEqual(summary["denial_events"], 3)
            self.assertEqual(set(manifest["evidence_hashes"]), {"transitions.json", "summary.json"})
            self.assertEqual(manifest["environment"]["environment_id"], "broker-state-machine-v1")
            self.assertFalse(manifest["trust_boundary"]["independent_failure_domain"])

    def test_process_trust_boundary_runner_records_unavailability_as_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            evidence = run_trust_boundary_evidence(out)
            summary = evidence["summary"]
            manifest = evidence["manifest"]
            self.assertEqual(summary["unexpected_authorizations"], 0)
            self.assertGreaterEqual(summary["separate_process_events"], 7)
            self.assertGreaterEqual(summary["fail_closed_events"], 4)
            self.assertEqual(manifest["trust_boundary"]["mode"], "same_host_process_reference")
            self.assertFalse(manifest["trust_boundary"]["independent_failure_domain"])
            self.assertEqual(set(manifest["evidence_hashes"]), {"events.json", "summary.json"})


if __name__ == "__main__":
    unittest.main()
