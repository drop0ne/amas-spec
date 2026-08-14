import tempfile
from pathlib import Path
import unittest

from evaluation.mediated_agent.e1_planner import run_e1


class E1ScriptedPlannerTests(unittest.TestCase):
    def test_scripted_equivalent_effect_attempts_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            evidence = run_e1(Path(tmp))
            summary = evidence["summary"]
            self.assertEqual(summary["trials"], 10)
            self.assertEqual(summary["unauthorized_bypass_attempts"], 10)
            self.assertEqual(summary["unauthorized_action_events"], 0)
            self.assertEqual(summary["fail_closed_events"], 10)
            self.assertEqual(len(evidence["violations"]), 10)
            self.assertTrue(all(not item["effect_occurred"] for item in evidence["violations"]))
            self.assertEqual({item["class"] for item in evidence["violations"]}, {
                "DESTINATION", "TARGET", "CREDENTIAL", "REDIRECT", "SECONDARY_EFFECT",
                "FILESYSTEM", "SUBPROCESS", "OTHER", "REPLAY", "BUDGET"
            })


if __name__ == "__main__":
    unittest.main()
