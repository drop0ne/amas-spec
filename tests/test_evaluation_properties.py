import tempfile
from pathlib import Path
import unittest

from evaluation.mediated_agent.harness import MediatedHarness, SyntheticAuthority
from evaluation.mediated_agent.runner import run_e0


class EvaluationPropertyTests(unittest.TestCase):
    def test_cartesian_scope_property_denied_actions_never_effect(self):
        authority = SyntheticAuthority(
            operations={"write"}, targets={"report"}, destinations={"mock://allowed"}
        )
        operations = ["write", "delete"]
        targets = ["report", "secret"]
        destinations = ["mock://allowed", "mock://forbidden"]
        redirects = [None, "mock://allowed", "mock://forbidden"]
        secondaries = [None, "mock://allowed", "mock://forbidden"]

        for operation in operations:
            for target in targets:
                for destination in destinations:
                    for redirect in redirects:
                        for secondary in secondaries:
                            parameters = {}
                            if redirect is not None:
                                parameters["redirect_to"] = redirect
                            if secondary is not None:
                                parameters["secondary_destination"] = secondary
                            harness = MediatedHarness(authority)
                            decision, effect = harness.submit({
                                "operation": operation,
                                "target": target,
                                "destination": destination,
                                "parameters": parameters,
                            })
                            effective_destination = redirect or destination
                            expected_allow = (
                                operation == "write"
                                and target == "report"
                                and effective_destination == "mock://allowed"
                                and secondary in (None, "mock://allowed")
                            )
                            self.assertEqual(decision.allowed, expected_allow)
                            self.assertEqual(effect is not None, expected_allow)
                            self.assertEqual(len(harness.evidence()["effects"]), 1 if expected_allow else 0)

    def test_unknown_proposal_field_fails_before_effect(self):
        harness = MediatedHarness(SyntheticAuthority(
            operations={"write"}, targets={"report"}, destinations={"mock://allowed"}
        ))
        with self.assertRaises(ValueError):
            harness.submit({
                "operation": "write",
                "target": "report",
                "destination": "mock://allowed",
                "parameters": {},
                "ambient_authority": "yes",
            })
        self.assertEqual(harness.evidence()["effects"], [])

    def test_e0_runner_emits_zero_unauthorized_effects(self):
        with tempfile.TemporaryDirectory() as tmp:
            evidence = run_e0(Path(tmp))
            self.assertEqual(evidence["summary"]["trials"], 4)
            self.assertEqual(evidence["summary"]["unauthorized_bypass_attempts"], 3)
            self.assertEqual(evidence["summary"]["unauthorized_action_events"], 0)
            self.assertEqual(evidence["summary"]["fail_closed_events"], 3)
            for name in ("evaluation_manifest.json", "trials.json", "results.json", "violations.json", "summary.json"):
                self.assertTrue((Path(tmp) / name).is_file(), name)


if __name__ == "__main__":
    unittest.main()
