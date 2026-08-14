import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator

from evaluation.mediated_agent.aab_harness import AABEvaluationHarness, request

ROOT = Path(__file__).resolve().parents[1]


class AABEvaluationHarnessTests(unittest.TestCase):
    def test_actual_aab_path_allows_authorized_synthetic_effect(self):
        harness = AABEvaluationHarness()
        try:
            result = harness.execute(request(sequence=1))
            self.assertEqual(result["decision"], "ALLOW")
            self.assertEqual(result["completion_status"], "SUCCEEDED")
            self.assertTrue(result["executed"])
            self.assertEqual(len(harness.adapter.events()), 1)
            self.assertEqual(harness.adapter.events()[0]["action_hash"], result["action_hash"])
            self.assertTrue(harness.broker.verify_receipts())
        finally:
            harness.close()

    def test_actual_aab_path_denies_direct_destination_scope_expansion(self):
        harness = AABEvaluationHarness()
        try:
            result = harness.execute(request(sequence=1, destination="mock://forbidden"))
            self.assertEqual(result["decision"], "DENY")
            self.assertFalse(result["executed"])
            self.assertEqual(harness.adapter.events(), ())
        finally:
            harness.close()

    def test_actual_aab_path_denies_redirect_and_secondary_effects(self):
        cases = [
            request(sequence=1, redirect_to="mock://forbidden"),
            request(sequence=1, secondary_destination="mock://forbidden"),
        ]
        for value in cases:
            with self.subTest(value=value):
                harness = AABEvaluationHarness()
                try:
                    result = harness.execute(value)
                    self.assertEqual(result["decision"], "DENY")
                    self.assertFalse(result["executed"])
                    self.assertEqual(harness.adapter.events(), ())
                finally:
                    harness.close()

    def test_post_effect_failure_is_unknown_then_reconciled_without_retry_authority(self):
        harness = AABEvaluationHarness()
        try:
            value = request(sequence=1, failure_mode="raise_after_effect")
            result = harness.execute(value)
            self.assertEqual(result["decision"], "ALLOW")
            self.assertEqual(result["completion_status"], "OUTCOME_UNKNOWN")
            self.assertIsNone(result["executed"])
            self.assertEqual(len(harness.adapter.events()), 1)

            reconciliation = harness.reconcile(result)
            self.assertEqual(reconciliation["reconciliation_state"], "EFFECT_CONFIRMED")
            self.assertFalse(reconciliation["retry_authorized"])
            schema = json.loads((ROOT / "evaluation" / "schemas" / "evaluation_reconciliation.schema.json").read_text(encoding="utf-8"))
            Draft202012Validator(schema).validate(reconciliation)

            repeated = harness.execute(value)
            self.assertEqual(repeated["decision"], "DENY")
            self.assertEqual(len(harness.adapter.events()), 1)
        finally:
            harness.close()


if __name__ == "__main__":
    unittest.main()
