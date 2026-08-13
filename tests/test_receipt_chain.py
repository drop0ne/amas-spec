import math
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = ROOT / "reference"
sys.path.insert(0, str(REFERENCE))

from receipt_chain import GENESIS, append_receipt, verify_chain


class ReceiptChainStrictJsonTests(unittest.TestCase):
    def test_valid_chain_verifies(self):
        first = append_receipt({"request_id": "R1", "decision": "ALLOW"}, sequence=0)
        second = append_receipt(
            {"request_id": "R2", "decision": "DENY"},
            previous_hash=first["receipt_hash"],
            sequence=1,
        )
        result = verify_chain([first, second])
        self.assertTrue(result["valid"])
        self.assertEqual(result["count"], 2)

    def test_non_finite_value_cannot_enter_chain(self):
        with self.assertRaises(ValueError):
            append_receipt({"request_id": "R1", "score": math.nan}, sequence=0)

    def test_non_object_receipt_fails_verification(self):
        result = verify_chain(["not-a-receipt"])
        self.assertFalse(result["valid"])
        self.assertEqual(result["reason"], "receipt_not_object")

    def test_invalid_previous_hash_rejected(self):
        with self.assertRaises(ValueError):
            append_receipt({"request_id": "R1"}, previous_hash="z" * 64, sequence=0)

    def test_mutation_detected(self):
        receipt = append_receipt({"request_id": "R1", "decision": "ALLOW"}, sequence=0)
        receipt["decision"] = "DENY"
        self.assertFalse(verify_chain([receipt])["valid"])

    def test_genesis_constant_is_lowercase_sha256_shape(self):
        self.assertEqual(GENESIS, "0" * 64)


if __name__ == "__main__":
    unittest.main()
