import json
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = ROOT / "reference"
SCHEMAS = ROOT / "schemas"
sys.path.insert(0, str(REFERENCE))

from enforcement_broker import EnforcementBroker, sign_lease

NOW = datetime(2026, 8, 12, 22, 30, tzinfo=timezone.utc)
KEY = b"receipt-schema-key"


def validator():
    schema = json.loads((SCHEMAS / "decision_receipt.schema.json").read_text(encoding="utf-8"))
    return Draft202012Validator(schema, format_checker=FormatChecker())


def lease():
    value = {
        "lease_version": 1,
        "lease_id": "L-RECEIPT",
        "issuer": "operator",
        "key_id": "K-RECEIPT",
        "issued_at": "2026-08-12T22:00:00Z",
        "not_before": "2026-08-12T22:00:00Z",
        "max_request_age_seconds": 300,
        "signature_alg": "HMAC-SHA256",
        "policy": {
            "policy_id": "P-RECEIPT",
            "principal": "agent",
            "objectives": ["inspect"],
            "operations": ["read"],
            "targets": ["sandbox://x"],
            "destinations": ["sandbox://x"],
            "credentials": [],
            "capability_contracts": [],
            "max_side_effect": "observe",
            "budgets": {"max_actions": 5, "max_network_calls": 1, "max_egress_bytes": 10, "max_wall_clock_seconds": 10},
            "max_delegation_depth": 0,
            "expires_at": "2026-08-13T00:00:00Z",
            "operator_escalation": False,
        },
    }
    value["signature"] = sign_lease(value, KEY)
    return value


def request(*, sequence=1, nonce="0123456789abcdef", target="sandbox://x"):
    return {
        "request_id": f"R{sequence}",
        "lease_id": "L-RECEIPT",
        "nonce": nonce,
        "sequence": sequence,
        "principal": "agent",
        "objective_id": "inspect",
        "operation": "read",
        "target": target,
        "destination": target,
        "credential_ref": None,
        "side_effect": "observe",
        "delegation_depth": 0,
        "timestamp": "2026-08-12T22:30:00Z",
    }


class DecisionReceiptSchemaTests(unittest.TestCase):
    def test_policy_evaluated_allow_receipt_validates(self):
        broker = EnforcementBroker(lease(), KEY)
        receipt = broker.authorize(
            request(),
            cost={"actions": 1, "network_calls": 0, "egress_bytes": 0, "wall_clock_seconds": 1},
            now=NOW,
        )
        self.assertEqual(receipt["decision"], "ALLOW")
        self.assertIn("policy_request_hash", receipt)
        validator().validate(receipt)

    def test_bound_allow_receipt_validates(self):
        broker = EnforcementBroker(lease(), KEY)
        receipt = broker.authorize(
            request(),
            cost={"actions": 1, "network_calls": 0, "egress_bytes": 0, "wall_clock_seconds": 1},
            now=NOW,
            execution_binding_hash="a" * 64,
        )
        self.assertEqual(receipt["execution_binding_hash"], "a" * 64)
        validator().validate(receipt)

    def test_pre_policy_bound_denial_validates_without_policy_request_hash(self):
        broker = EnforcementBroker(lease(), KEY)
        bad = request(sequence=2)
        receipt = broker.authorize(
            bad,
            cost={"actions": 1, "network_calls": 0, "egress_bytes": 0, "wall_clock_seconds": 1},
            now=NOW,
            execution_binding_hash="b" * 64,
        )
        self.assertEqual(receipt["decision"], "DENY")
        self.assertNotIn("policy_request_hash", receipt)
        self.assertEqual(receipt["execution_binding_hash"], "b" * 64)
        validator().validate(receipt)


if __name__ == "__main__":
    unittest.main()
