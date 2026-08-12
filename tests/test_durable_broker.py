import copy
import json
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

REFERENCE = Path(__file__).resolve().parents[1] / "reference"
sys.path.insert(0, str(REFERENCE))

from durable_broker import DurableEnforcementBroker, DurabilityError, verify_checkpoint
from enforcement_broker import sign_lease

NOW = datetime(2026, 8, 12, 22, 0, tzinfo=timezone.utc)
LEASE_KEY = b"lease-key-for-tests"
STATE_KEY = b"state-key-for-tests"
CHECKPOINT_KEY = b"checkpoint-key-for-tests"
COST = {"actions": 1, "network_calls": 1, "egress_bytes": 10, "wall_clock_seconds": 1}


def lease():
    value = {
        "lease_id": "LEASE-1",
        "issuer": "operator",
        "issued_at": "2026-08-12T21:00:00Z",
        "max_request_age_seconds": 300,
        "signature_alg": "HMAC-SHA256",
        "policy": {
            "policy_id": "P1",
            "principal": "agent",
            "objectives": ["obj"],
            "operations": ["read"],
            "targets": ["sandbox://a"],
            "destinations": ["sandbox://a"],
            "credentials": [],
            "max_side_effect": "simulate",
            "budgets": {
                "max_actions": 10,
                "max_network_calls": 5,
                "max_egress_bytes": 1000,
                "max_wall_clock_seconds": 60,
            },
            "max_delegation_depth": 0,
            "expires_at": "2026-08-13T00:00:00Z",
            "operator_escalation": False,
        },
    }
    value["signature"] = sign_lease(value, LEASE_KEY)
    return value


def request(seq=1, nonce="nonce-1"):
    return {
        "request_id": f"R{seq}",
        "lease_id": "LEASE-1",
        "nonce": nonce,
        "sequence": seq,
        "principal": "agent",
        "objective_id": "obj",
        "operation": "read",
        "target": "sandbox://a",
        "destination": "sandbox://a",
        "credential_ref": None,
        "side_effect": "observe",
        "timestamp": "2026-08-12T22:00:00Z",
    }


class DurableBrokerTests(unittest.TestCase):
    def test_restart_preserves_authoritative_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "broker-state.json"
            first = DurableEnforcementBroker(lease(), LEASE_KEY, state_path=path, state_key=STATE_KEY)
            receipt = first.authorize(request(), cost=COST, now=NOW)
            self.assertEqual(receipt["decision"], "ALLOW")
            generation = first.state_generation

            restored = DurableEnforcementBroker(lease(), LEASE_KEY, state_path=path, state_key=STATE_KEY)
            self.assertEqual(restored.state_generation, generation)
            self.assertEqual(restored.last_sequence, 1)
            self.assertEqual(restored.usage["network_calls"], 1)
            self.assertIn("nonce-1", restored.seen_nonces)
            self.assertTrue(restored.verify_receipts())

    def test_replay_remains_denied_after_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "broker-state.json"
            broker = DurableEnforcementBroker(lease(), LEASE_KEY, state_path=path, state_key=STATE_KEY)
            broker.authorize(request(), cost=COST, now=NOW)
            restored = DurableEnforcementBroker(lease(), LEASE_KEY, state_path=path, state_key=STATE_KEY)
            denied = restored.authorize(request(), cost=COST, now=NOW)
            self.assertEqual(denied["decision"], "DENY")
            self.assertEqual(denied["reason"], "replay_nonce")

    def test_tampered_state_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "broker-state.json"
            DurableEnforcementBroker(lease(), LEASE_KEY, state_path=path, state_key=STATE_KEY)
            raw = json.loads(path.read_text(encoding="utf-8"))
            raw["usage"]["actions"] = 999
            path.write_text(json.dumps(raw), encoding="utf-8")
            with self.assertRaises(DurabilityError):
                DurableEnforcementBroker(lease(), LEASE_KEY, state_path=path, state_key=STATE_KEY)

    def test_signed_checkpoint_verifies(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "broker-state.json"
            broker = DurableEnforcementBroker(lease(), LEASE_KEY, state_path=path, state_key=STATE_KEY)
            broker.authorize(request(), cost=COST, now=NOW)
            checkpoint = broker.create_checkpoint(CHECKPOINT_KEY, now=NOW)
            self.assertTrue(verify_checkpoint(checkpoint, CHECKPOINT_KEY))

    def test_tampered_checkpoint_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "broker-state.json"
            broker = DurableEnforcementBroker(lease(), LEASE_KEY, state_path=path, state_key=STATE_KEY)
            checkpoint = broker.create_checkpoint(CHECKPOINT_KEY, now=NOW)
            checkpoint["generation"] += 1
            with self.assertRaises(DurabilityError):
                DurableEnforcementBroker(
                    lease(), LEASE_KEY, state_path=path, state_key=STATE_KEY,
                    checkpoint=checkpoint, checkpoint_key=CHECKPOINT_KEY,
                )

    def test_checkpoint_detects_validly_authenticated_rollback(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "broker-state.json"
            broker = DurableEnforcementBroker(lease(), LEASE_KEY, state_path=path, state_key=STATE_KEY)
            old_state = path.read_bytes()
            broker.authorize(request(), cost=COST, now=NOW)
            checkpoint = broker.create_checkpoint(CHECKPOINT_KEY, now=NOW)

            # Restore an older state file that still has a valid MAC. Integrity
            # alone accepts it; the independently retained checkpoint must not.
            path.write_bytes(old_state)
            with self.assertRaisesRegex(DurabilityError, "rollback detected"):
                DurableEnforcementBroker(
                    lease(), LEASE_KEY, state_path=path, state_key=STATE_KEY,
                    checkpoint=checkpoint, checkpoint_key=CHECKPOINT_KEY,
                )

    def test_exact_checkpoint_restore_succeeds(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "broker-state.json"
            broker = DurableEnforcementBroker(lease(), LEASE_KEY, state_path=path, state_key=STATE_KEY)
            broker.authorize(request(), cost=COST, now=NOW)
            checkpoint = broker.create_checkpoint(CHECKPOINT_KEY, now=NOW)
            restored = DurableEnforcementBroker(
                lease(), LEASE_KEY, state_path=path, state_key=STATE_KEY,
                checkpoint=checkpoint, checkpoint_key=CHECKPOINT_KEY,
            )
            self.assertEqual(restored.state_hash, checkpoint["state_hash"])


if __name__ == "__main__":
    unittest.main()
