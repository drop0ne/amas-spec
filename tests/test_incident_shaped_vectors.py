import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = ROOT / "reference"
VECTORS = ROOT / "adversarial" / "incident_shaped_vectors.json"
sys.path.insert(0, str(REFERENCE))

from capability_contract import bind_contract_id, validate_contract


class IncidentShapedVectorTests(unittest.TestCase):
    def test_incident_shaped_capability_vectors(self):
        corpus = json.loads(VECTORS.read_text(encoding="utf-8"))
        contract = bind_contract_id(corpus["contract_body"])
        for vector in corpus["vectors"]:
            with self.subTest(vector=vector["id"]):
                result = validate_contract(
                    contract,
                    adapter_id=contract["adapter_id"],
                    broker_request=corpus["broker_request"],
                    parameters=vector["parameters"],
                    security_effects=vector["security_effects"],
                )
                self.assertEqual(result["valid"], vector["expected_valid"], result)
                self.assertEqual(result["reason"], vector["expected_reason"], result)


if __name__ == "__main__":
    unittest.main()
