import copy
import importlib.util
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

REFERENCE = Path(__file__).resolve().parents[1] / "reference"
sys.path.insert(0, str(REFERENCE))
MODULE = REFERENCE / "enforcement_broker.py"
spec = importlib.util.spec_from_file_location("enforcement_broker", MODULE)
broker_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(broker_mod)

NOW = datetime(2026, 8, 12, 22, 30, tzinfo=timezone.utc)
KEY = b"reference-test-key-not-for-production"


def policy():
    return {
        "policy_id": "P-BROKER-1",
        "principal": "agent-A",
        "objectives": ["obj-read"],
        "operations": ["read"],
        "targets": ["sandbox://dataset"],
        "destinations": ["sandbox://dataset"],
        "credentials": [],
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
    }


def lease():
    value = {
        "lease_id": "LEASE-1",
        "issuer": "operator-root",
        "issued_at": "2026-08-12T22:00:00Z",
        "max_request_age_seconds": 120,
        "signature_alg": "HMAC-SHA256",
        "policy": policy(),
    }
    value["signature"] = broker_mod.sign_lease(value, KEY)
    return value


def request(sequence=1, nonce="0123456789abcdef", timestamp="2026-08-12T22:30:00Z"):
    return {
        "request_id": f"R-{sequence}",
        "lease_id": "LEASE-1",
        "nonce": nonce,
        "sequence": sequence,
        "principal": "agent-A",
        "objective_id": "obj-read",
        "operation": "read",
        "target": "sandbox://dataset",
        "destination": "sandbox://dataset",
        "credential_ref": None,
        "side_effect": "observe",
        "delegation_depth": 0,
        "timestamp": timestamp,
    }


def cost(actions=1, network_calls=0, egress_bytes=0, wall_clock_seconds=1):
    return {
        "actions": actions,
        "network_calls": network_calls,
        "egress_bytes": egress_bytes,
        "wall_clock_seconds": wall_clock_seconds,
    }


class EnforcementBrokerTests(unittest.TestCase):
    def test_signed_lease_verifies(self):
        value = lease()
        self.assertTrue(broker_mod.verify_lease_signature(value, KEY))

    def test_tampered_lease_fails_closed(self):
        value = lease()
        value["policy"]["targets"].append("external://unexpected")
        with self.assertRaises(ValueError):
            broker_mod.EnforcementBroker(value, KEY)

    def test_authorized_request_and_receipt_chain(self):
        broker = broker_mod.EnforcementBroker(lease(), KEY)
        receipt = broker.authorize(request(), cost=cost(network_calls=1, egress_bytes=10), now=NOW)
        self.assertEqual(receipt["decision"], "ALLOW")
        self.assertEqual(receipt["lease_id"], "LEASE-1")
        self.assertEqual(receipt["authoritative_usage"]["actions"], 1)
        self.assertTrue(broker.verify_receipts())

    def test_replayed_nonce_denied(self):
        broker = broker_mod.EnforcementBroker(lease(), KEY)
        broker.authorize(request(), cost=cost(), now=NOW)
        replay = request(sequence=2, nonce="0123456789abcdef")
        receipt = broker.authorize(replay, cost=cost(), now=NOW)
        self.assertEqual(receipt["decision"], "DENY")
        self.assertEqual(receipt["reason"], "replay_nonce")

    def test_sequence_gap_denied(self):
        broker = broker_mod.EnforcementBroker(lease(), KEY)
        receipt = broker.authorize(request(sequence=2), cost=cost(), now=NOW)
        self.assertEqual(receipt["decision"], "DENY")
        self.assertEqual(receipt["reason"], "sequence_violation")

    def test_stale_request_denied(self):
        broker = broker_mod.EnforcementBroker(lease(), KEY)
        stale = (NOW - timedelta(seconds=121)).isoformat().replace("+00:00", "Z")
        receipt = broker.authorize(request(timestamp=stale), cost=cost(), now=NOW)
        self.assertEqual(receipt["decision"], "DENY")
        self.assertEqual(receipt["reason"], "stale_request")

    def test_future_request_denied(self):
        broker = broker_mod.EnforcementBroker(lease(), KEY)
        future = (NOW + timedelta(seconds=31)).isoformat().replace("+00:00", "Z")
        receipt = broker.authorize(request(timestamp=future), cost=cost(), now=NOW)
        self.assertEqual(receipt["decision"], "DENY")
        self.assertEqual(receipt["reason"], "request_from_future")

    def test_broker_owned_cumulative_budget(self):
        broker = broker_mod.EnforcementBroker(lease(), KEY)
        first = broker.authorize(request(), cost=cost(network_calls=1), now=NOW)
        self.assertEqual(first["decision"], "ALLOW")
        second = broker.authorize(
            request(sequence=2, nonce="fedcba9876543210"),
            cost=cost(network_calls=1),
            now=NOW,
        )
        self.assertEqual(second["decision"], "ALLOW")
        third = broker.authorize(
            request(sequence=3, nonce="0011223344556677"),
            cost=cost(network_calls=1),
            now=NOW,
        )
        self.assertEqual(third["decision"], "DENY")
        self.assertEqual(third["reason"], "network_budget")
        self.assertEqual(broker.snapshot()["usage"]["network_calls"], 2)
        self.assertEqual(broker.snapshot()["usage"]["actions"], 3)

    def test_request_cannot_supply_fake_usage(self):
        broker = broker_mod.EnforcementBroker(lease(), KEY)
        r = request()
        r["usage"] = {"actions": 0, "network_calls": 0, "egress_bytes": 0, "wall_clock_seconds": 0}
        receipt = broker.authorize(r, cost=cost(network_calls=1, egress_bytes=10), now=NOW)
        self.assertEqual(receipt["decision"], "ALLOW")
        self.assertEqual(receipt["authoritative_usage"]["network_calls"], 1)
        self.assertEqual(receipt["authoritative_usage"]["egress_bytes"], 10)

    def test_receipt_mutation_detected(self):
        broker = broker_mod.EnforcementBroker(lease(), KEY)
        broker.authorize(request(), cost=cost(), now=NOW)
        broker.receipts[0]["reason"] = "tampered"
        self.assertFalse(broker.verify_receipts())

    def test_invalid_cost_fails_closed(self):
        broker = broker_mod.EnforcementBroker(lease(), KEY)
        receipt = broker.authorize(request(), cost={"actions": 0}, now=NOW)
        self.assertEqual(receipt["decision"], "DENY")
        self.assertTrue(receipt["reason"].startswith("invalid_envelope:"))


if __name__ == "__main__":
    unittest.main()
