import json
import multiprocessing
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = ROOT / "reference"
sys.path.insert(0, str(REFERENCE))

from bounded_durable_broker import BoundedDurableEnforcementBroker
from durable_broker import DurableEnforcementBroker, DurabilityError
from enforcement_broker import RevocationRegistry, sign_lease

NOW = datetime(2026, 8, 14, 21, 30, tzinfo=timezone.utc)
LEASE_KEY = b"evaluation-state-machine-lease-key"
STATE_KEY = b"evaluation-state-machine-state-key"
CHECKPOINT_KEY = b"evaluation-state-machine-checkpoint-key"
COST = {"actions": 1, "network_calls": 1, "egress_bytes": 8, "wall_clock_seconds": 1}


def make_lease(*, max_actions=8, max_network_calls=8, expires="2026-08-15T23:59:59Z"):
    value = {
        "lease_version": 1, "lease_id": "EVAL-SM-LEASE", "issuer": "evaluation-operator", "key_id": "eval-sm-key",
        "issued_at": "2026-08-14T20:00:00Z", "not_before": "2026-08-14T20:00:00Z",
        "max_request_age_seconds": 7200, "signature_alg": "HMAC-SHA256",
        "policy": {
            "policy_id": "EVAL-SM-POLICY", "principal": "evaluation-agent", "objectives": ["inspect"],
            "operations": ["read"], "targets": ["mock://allowed"], "destinations": ["mock://allowed"],
            "credentials": [], "capability_contracts": [], "max_side_effect": "observe",
            "budgets": {"max_actions": max_actions, "max_network_calls": max_network_calls, "max_egress_bytes": 4096, "max_wall_clock_seconds": 300},
            "max_delegation_depth": 0, "expires_at": expires, "operator_escalation": False,
        },
    }
    value["signature"] = sign_lease(value, LEASE_KEY)
    return value


def req(sequence, *, nonce=None, destination="mock://allowed", timestamp="2026-08-14T21:30:00Z"):
    return {
        "request_id": f"SM-R{sequence}", "lease_id": "EVAL-SM-LEASE",
        "nonce": nonce or f"state-machine-nonce-{sequence:06d}", "sequence": sequence,
        "principal": "evaluation-agent", "objective_id": "inspect", "operation": "read",
        "target": destination, "destination": destination, "credential_ref": None, "side_effect": "observe",
        "timestamp": timestamp,
    }


def _race_worker(state_path, start_event, queue, nonce):
    sys.path.insert(0, str(REFERENCE))
    broker = DurableEnforcementBroker(make_lease(), LEASE_KEY, state_path=state_path, state_key=STATE_KEY)
    start_event.wait(10)
    receipt = broker.authorize(req(1, nonce=nonce), cost=COST, now=NOW)
    queue.put((receipt["decision"], receipt["reason"]))


class BrokerStateMachineTests(unittest.TestCase):
    def test_composed_restart_replay_scope_budget_and_checkpoint_sequence(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            broker = DurableEnforcementBroker(make_lease(max_actions=4, max_network_calls=2), LEASE_KEY, state_path=path, state_key=STATE_KEY)

            first = broker.authorize(req(1), cost=COST, now=NOW)
            self.assertEqual(first["decision"], "ALLOW")

            broker = DurableEnforcementBroker(make_lease(max_actions=4, max_network_calls=2), LEASE_KEY, state_path=path, state_key=STATE_KEY)
            replay = broker.authorize(req(1), cost=COST, now=NOW)
            self.assertEqual((replay["decision"], replay["reason"]), ("DENY", "replay_nonce"))

            scope_denial = broker.authorize(req(2, destination="mock://forbidden"), cost=COST, now=NOW)
            self.assertEqual(scope_denial["decision"], "DENY")
            self.assertEqual(broker.last_sequence, 2)
            self.assertEqual(broker.usage["network_calls"], 1)
            self.assertEqual(broker.usage["actions"], 2)

            third = broker.authorize(req(3), cost=COST, now=NOW)
            self.assertEqual(third["decision"], "ALLOW")
            self.assertEqual(broker.usage["network_calls"], 2)
            checkpoint = broker.create_checkpoint(CHECKPOINT_KEY, now=NOW)

            fourth = broker.authorize(req(4), cost=COST, now=NOW)
            self.assertEqual((fourth["decision"], fourth["reason"]), ("DENY", "network_budget"))
            self.assertTrue(broker.verify_receipts())

            restored = DurableEnforcementBroker(
                make_lease(max_actions=4, max_network_calls=2), LEASE_KEY, state_path=path, state_key=STATE_KEY,
                checkpoint=checkpoint, checkpoint_key=CHECKPOINT_KEY,
            )
            self.assertEqual(restored.last_sequence, 4)
            self.assertEqual(restored.usage["network_calls"], 2)
            self.assertEqual(restored.usage["actions"], 4)
            self.assertTrue(restored.verify_receipts())

    def test_revocation_and_expiry_fail_closed_without_effective_authority_advance(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            registry = RevocationRegistry()
            broker = DurableEnforcementBroker(
                make_lease(), LEASE_KEY, state_path=path, state_key=STATE_KEY, revocation_checker=registry.is_revoked
            )
            self.assertEqual(broker.authorize(req(1), cost=COST, now=NOW)["decision"], "ALLOW")
            registry.revoke("EVAL-SM-LEASE")
            revoked = broker.authorize(req(2), cost=COST, now=NOW)
            self.assertEqual((revoked["decision"], revoked["reason"]), ("DENY", "lease_revoked"))
            self.assertEqual(broker.last_sequence, 1)
            self.assertNotIn(req(2)["nonce"], broker.seen_nonces)

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "expired.json"
            expiry = "2026-08-14T21:35:00Z"
            broker = DurableEnforcementBroker(make_lease(expires=expiry), LEASE_KEY, state_path=path, state_key=STATE_KEY)
            expired = broker.authorize(req(1, timestamp="2026-08-14T21:36:00Z"), cost=COST, now=NOW + timedelta(minutes=6))
            self.assertEqual(expired["decision"], "DENY")
            self.assertEqual(expired["reason"], "policy_freshness")
            self.assertEqual(broker.last_sequence, 1)
            self.assertEqual(broker.usage["network_calls"], 0)

    def test_checkpoint_blocks_authenticated_rollback_after_mixed_decisions(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            broker = DurableEnforcementBroker(make_lease(), LEASE_KEY, state_path=path, state_key=STATE_KEY)
            broker.authorize(req(1), cost=COST, now=NOW)
            old_state = path.read_bytes()
            broker.authorize(req(2, destination="mock://forbidden"), cost=COST, now=NOW)
            checkpoint = broker.create_checkpoint(CHECKPOINT_KEY, now=NOW)
            broker.authorize(req(3), cost=COST, now=NOW)

            path.write_bytes(old_state)
            with self.assertRaisesRegex(DurabilityError, "rollback detected"):
                DurableEnforcementBroker(
                    make_lease(), LEASE_KEY, state_path=path, state_key=STATE_KEY,
                    checkpoint=checkpoint, checkpoint_key=CHECKPOINT_KEY,
                )

    def test_bounded_epoch_counts_denials_and_refuses_silent_compaction(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            broker = BoundedDurableEnforcementBroker(
                make_lease(), LEASE_KEY, state_path=path, state_key=STATE_KEY, max_epoch_events=3
            )
            self.assertEqual(broker.authorize(req(1), cost=COST, now=NOW)["decision"], "ALLOW")
            self.assertEqual(broker.authorize(req(2, destination="mock://forbidden"), cost=COST, now=NOW)["decision"], "DENY")
            self.assertEqual(broker.authorize(req(3), cost=COST, now=NOW)["decision"], "ALLOW")
            self.assertTrue(broker.capacity()["rotation_required"])
            state_before = path.read_bytes()
            with self.assertRaisesRegex(DurabilityError, "checkpoint and rotate"):
                broker.authorize(req(4), cost=COST, now=NOW)
            self.assertEqual(path.read_bytes(), state_before)
            self.assertEqual(len(broker.receipts), 3)

    def test_actual_multiprocess_sequence_race_allows_at_most_one_spend(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            DurableEnforcementBroker(make_lease(), LEASE_KEY, state_path=path, state_key=STATE_KEY)
            ctx = multiprocessing.get_context("spawn")
            start = ctx.Event()
            queue = ctx.Queue()
            workers = [
                ctx.Process(target=_race_worker, args=(str(path), start, queue, "race-nonce-0000000001")),
                ctx.Process(target=_race_worker, args=(str(path), start, queue, "race-nonce-0000000002")),
            ]
            for worker in workers:
                worker.start()
            start.set()
            results = [queue.get(timeout=20) for _ in workers]
            for worker in workers:
                worker.join(timeout=20)
                self.assertEqual(worker.exitcode, 0)

            decisions = sorted(decision for decision, _ in results)
            self.assertEqual(decisions, ["ALLOW", "DENY"])
            restored = DurableEnforcementBroker(make_lease(), LEASE_KEY, state_path=path, state_key=STATE_KEY)
            self.assertEqual(restored.last_sequence, 1)
            self.assertEqual(restored.usage["actions"], 1)
            self.assertEqual(restored.usage["network_calls"], 1)
            self.assertEqual(len(restored.receipts), 2)
            self.assertTrue(restored.verify_receipts())

    def test_corrupt_authenticated_state_shape_fails_before_authorization(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "state.json"
            DurableEnforcementBroker(make_lease(), LEASE_KEY, state_path=path, state_key=STATE_KEY)
            raw = json.loads(path.read_text(encoding="utf-8"))
            raw["ancestor_state_hashes"] = ["0" * 64]
            path.write_text(json.dumps(raw), encoding="utf-8")
            with self.assertRaises(DurabilityError):
                DurableEnforcementBroker(make_lease(), LEASE_KEY, state_path=path, state_key=STATE_KEY)


if __name__ == "__main__":
    unittest.main()
