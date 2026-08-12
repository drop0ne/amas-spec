import copy
import importlib.util
import json
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "reference" / "authority_gate.py"
spec = importlib.util.spec_from_file_location("authority_gate", MODULE)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

CORPUS = json.loads((ROOT / "adversarial" / "aab_vectors.json").read_text(encoding="utf-8"))
NOW = datetime(2026, 8, 12, 18, 0, tzinfo=timezone.utc)


def apply_vector(base, vector):
    req = copy.deepcopy(base)
    for key, value in vector.get("patch", {}).items():
        req[key] = copy.deepcopy(value)
    for key in vector.get("delete", []):
        req.pop(key, None)
    req["request_id"] = vector["id"]
    return req


class AdversarialCorpusTests(unittest.TestCase):
    def test_all_vectors(self):
        failures = []
        for vector in CORPUS["vectors"]:
            request = apply_vector(CORPUS["base_request"], vector)
            receipt = gate.evaluate(CORPUS["policy"], request, NOW)
            expected = (vector["expected_decision"], vector["expected_reason"])
            actual = (receipt["decision"], receipt["reason"])
            if actual != expected:
                failures.append((vector["id"], vector["name"], expected, actual))
        self.assertEqual(failures, [], f"adversarial vector failures: {failures}")

    def test_corpus_has_minimum_coverage(self):
        self.assertGreaterEqual(len(CORPUS["vectors"]), 20)
        names = " ".join(v["name"] for v in CORPUS["vectors"]).lower()
        for term in ("target", "destination", "credential", "budget", "delegation", "principal"):
            self.assertIn(term, names)


if __name__ == "__main__":
    unittest.main()
