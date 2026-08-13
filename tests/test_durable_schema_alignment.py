import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = ROOT / "reference"
SCHEMAS = ROOT / "schemas"
sys.path.insert(0, str(REFERENCE))

from durable_broker import DurableEnforcementBroker
from enforcement_broker import sign_lease

NOW = datetime(2026, 8, 12, 22, 30, tzinfo=timezone.utc)
LEASE_KEY = b"durable-schema-lease-key"
STATE_KEY = b"durable-schema-state-key"
CHECKPOINT_KEY = b"durable-schema-checkpoint-key"


def load_schema(name):
    return json.loads((SCHEMAS / name).read_text(encoding="utf-8"))


def lease():
    value = {
        "lease_version": 1,
        "lease_id": "LEASE-SCHEMA",
        "issuer": "operator",
        "key_id": "lease-key-1",
        "issued_at": "2026-08-12T22:00:00Z",
        "not_before": "2026-08-12T22:00:00Z",
        "max_request_age_seconds": 300,
        "signature_alg": "HMAC-SHA256",
        "policy": {
            "policy_id": "P-SCHEMA",
            "principal": "agent",
            "objectives": ["inspect"],
            "operations": ["read"],
            "targets": ["sandbox://x"],
            "destinations": ["sandbox://x"],
            "credentials": [],
            "capability_contracts": [],
            "max_side_effect": "observe",
            "budgets": {
                "max_actions": 3,
                "max_network_calls": 2,
                "max_egress_bytes": 100,
                "max_wall_clock_seconds": 30,
            },
            "max_delegation_depth": 0,
            "expires_at": "2026-08-13T00:00:00Z",
            "operator_escalation": False,
        },
    }
    value["signature"] = sign_lease(value, LEASE_KEY)
    return value


def request(sequence=1, nonce="0123456789abcdef"):
    return {
        "request_id": f"R{sequence}",
        "lease_id": "LEASE-SCHEMA",
        "nonce": nonce,
        "sequence": sequence,
        "principal": "agent",
        "objective_id": "inspect",
        "operation": "read",
        "target": "sandbox://x",
        "destination": "sandbox://x",
        "credential_ref": None,
        "side_effect": "observe",
        "delegation_depth": 0,
        "timestamp": "2026-08-12T22:30:00Z",
    }


class DurableSchemaAlignmentTests(unittest.TestCase):
    def validate(self, name, value):
        Draft202012Validator(
            load_schema(name),
            format_checker=FormatChecker(),
        ).validate(value)

    def test_initial_and_post_authorization_state_validate(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "broker-state.json"
            broker = DurableEnforcementBroker(
                lease(), LEASE_KEY,
                state_path=state_path,
                state_key=STATE_KEY,
            )
            self.validate("broker_state.schema.json", json.loads(state_path.read_text(encoding="utf-8")))

            receipt = broker.authorize(
                request(),
                cost={"actions": 1, "network_calls": 1, "egress_bytes": 10, "wall_clock_seconds": 1},
                now=NOW,
                execution_binding_hash="a" * 64,
            )
            self.assertEqual(receipt["decision"], "ALLOW")
            self.validate("decision_receipt.schema.json", receipt)
            self.validate("broker_state.schema.json", json.loads(state_path.read_text(encoding="utf-8")))

    def test_checkpoint_validates_against_schema(self):
        with tempfile.TemporaryDirectory() as tmp:
            state_path = Path(tmp) / "broker-state.json"
            broker = DurableEnforcementBroker(
                lease(), LEASE_KEY,
                state_path=state_path,
                state_key=STATE_KEY,
            )
            broker.authorize(
                request(),
                cost={"actions": 1, "network_calls": 0, "egress_bytes": 0, "wall_clock_seconds": 1},
                now=NOW,
            )
            checkpoint = broker.create_checkpoint(CHECKPOINT_KEY, now=NOW)
            self.validate("broker_checkpoint.schema.json", checkpoint)


if __name__ == "__main__":
    unittest.main()
