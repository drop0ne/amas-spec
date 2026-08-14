import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = ROOT / "reference"
sys.path.insert(0, str(REFERENCE))
from bounded_durable_broker import BoundedDurableEnforcementBroker
from durable_broker import DurabilityError
from enforcement_broker import sign_lease

NOW = datetime(2026, 8, 12, 22, 30, tzinfo=timezone.utc)
KEY = b"bounded-broker-verification-key"
STATE_KEY = b"bounded-broker-state-key"


def lease():
    value = {"lease_version": 1, "lease_id": "L-BOUND", "issuer": "operator", "key_id": "K-BOUND", "issued_at": "2026-08-12T22:00:00Z", "not_before": "2026-08-12T22:00:00Z", "max_request_age_seconds": 3600, "signature_alg": "HMAC-SHA256", "policy": {"policy_id": "P-BOUND", "principal": "agent", "objectives": ["inspect"], "operations": ["read"], "targets": ["sandbox://data"], "destinations": ["sandbox://data"], "credentials": [], "capability_contracts": [], "max_side_effect": "observe", "budgets": {"max_actions": 10, "max_network_calls": 10, "max_egress_bytes": 1000, "max_wall_clock_seconds": 100}, "max_delegation_depth": 0, "expires_at": "2026-08-13T00:00:00Z", "operator_escalation": False}}
    value["signature"] = sign_lease(value, KEY)
    return value


def request(sequence, nonce):
    return {"request_id": f"R-{sequence}", "lease_id": "L-BOUND", "nonce": nonce, "sequence": sequence, "principal": "agent", "objective_id": "inspect", "operation": "read", "target": "sandbox://data", "destination": "sandbox://data", "credential_ref": None, "side_effect": "observe", "delegation_depth": 0, "timestamp": "2026-08-12T22:30:00Z"}


class BoundedDurableBrokerTests(unittest.TestCase):
    def test_epoch_capacity_requires_rotation(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            broker = BoundedDurableEnforcementBroker(lease(), KEY, state_path=path, state_key=STATE_KEY, max_epoch_events=2)
            cost = {"actions": 1, "network_calls": 0, "egress_bytes": 0, "wall_clock_seconds": 1}
            self.assertEqual(broker.authorize(request(1, "nonce-00000000001"), cost=cost, now=NOW)["decision"], "ALLOW")
            self.assertEqual(broker.authorize(request(2, "nonce-00000000002"), cost=cost, now=NOW)["decision"], "ALLOW")
            self.assertTrue(broker.capacity()["rotation_required"])
            with self.assertRaises(DurabilityError):
                broker.authorize(request(3, "nonce-00000000003"), cost=cost, now=NOW)
            self.assertEqual(len(broker.receipts), 2)

    def test_reopen_honors_tighter_epoch_ceiling(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"; cost = {"actions": 1, "network_calls": 0, "egress_bytes": 0, "wall_clock_seconds": 1}
            first = BoundedDurableEnforcementBroker(lease(), KEY, state_path=path, state_key=STATE_KEY, max_epoch_events=2)
            first.authorize(request(1, "nonce-00000000001"), cost=cost, now=NOW); first.authorize(request(2, "nonce-00000000002"), cost=cost, now=NOW)
            with self.assertRaises(DurabilityError):
                BoundedDurableEnforcementBroker(lease(), KEY, state_path=path, state_key=STATE_KEY, max_epoch_events=1)


if __name__ == "__main__": unittest.main()
