import hashlib
import json
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = ROOT / "reference"
sys.path.insert(0, str(REFERENCE))

import canonical_json


class CanonicalGoldenVectorTests(unittest.TestCase):
    def test_python_matches_portable_golden_vectors(self):
        vectors = json.loads((ROOT / "evaluation" / "corpora" / "canonical_json_vectors.json").read_text(encoding="utf-8"))
        self.assertGreaterEqual(len(vectors), 5)
        for vector in vectors:
            with self.subTest(vector=vector["name"]):
                encoded = canonical_json.dumps(vector["value"])
                self.assertEqual(encoded, vector["canonical"])
                self.assertEqual(hashlib.sha256(encoded.encode("utf-8")).hexdigest(), vector["sha256"])


if __name__ == "__main__":
    unittest.main()
