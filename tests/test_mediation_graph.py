import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = ROOT / "reference"
sys.path.insert(0, str(REFERENCE))

from mediation_graph import verify_mediation_graph


class MediationGraphTests(unittest.TestCase):
    def test_bypass_corpus(self):
        corpus = json.loads((ROOT / "adversarial" / "bypass_topologies.json").read_text(encoding="utf-8"))
        self.assertGreaterEqual(len(corpus), 10)
        for vector in corpus:
            with self.subTest(vector=vector["id"]):
                result = verify_mediation_graph(vector["graph"])
                self.assertEqual(result["valid"], vector["expected_valid"], result)

    def test_clean_path_reports_mediated_path(self):
        graph = {
            "nodes": {"agent":"agent","broker":"broker","tool":"adapter","sink":"side_effect"},
            "edges": [["agent","broker"],["broker","tool"],["tool","sink"]],
        }
        result = verify_mediation_graph(graph)
        self.assertTrue(result["valid"])
        self.assertEqual(result["bypass_paths"], [])
        self.assertEqual(result["mediated_paths"], [["agent","broker","tool","sink"]])

    def test_direct_bypass_exposes_path(self):
        graph = {
            "nodes": {"agent":"agent","broker":"broker","sink":"side_effect"},
            "edges": [["agent","broker"],["broker","sink"],["agent","sink"]],
        }
        result = verify_mediation_graph(graph)
        self.assertFalse(result["valid"])
        self.assertIn(["agent","sink"], result["bypass_paths"])

    def test_malformed_graph_fails_closed(self):
        result = verify_mediation_graph({"nodes": {"agent":"agent"}, "edges": [["agent","missing"]]})
        self.assertFalse(result["valid"])
        self.assertTrue(result["reason"].startswith("invalid_graph:"))


if __name__ == "__main__":
    unittest.main()
