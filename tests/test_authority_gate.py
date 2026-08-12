import importlib.util
import unittest
from datetime import datetime, timezone
from pathlib import Path

MODULE = Path(__file__).resolve().parents[1] / "reference" / "authority_gate.py"
spec = importlib.util.spec_from_file_location("authority_gate", MODULE)
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

NOW = datetime(2026, 8, 12, 18, 0, tzinfo=timezone.utc)


def policy():
    return {
        "policy_id": "P1",
        "principal": "agent",
        "objectives": ["obj"],
        "operations": ["read"],
        "targets": ["sandbox://a"],
        "destinations": ["sandbox://a"],
        "credentials": [],
        "max_side_effect": "simulate",
        "budgets": {"max_actions": 5, "max_network_calls": 2, "max_egress_bytes": 1000, "max_wall_clock_seconds": 60},
        "max_delegation_depth": 0,
        "expires_at": "2026-08-13T00:00:00Z",
        "operator_escalation": True,
    }


def request():
    return {
        "request_id": "R1",
        "principal": "agent",
        "objective_id": "obj",
        "operation": "read",
        "target": "sandbox://a",
        "destination": "sandbox://a",
        "credential_ref": None,
        "side_effect": "observe",
        "usage": {"actions": 1, "network_calls": 1, "egress_bytes": 10, "wall_clock_seconds": 1},
        "delegation_depth": 0,
        "timestamp": "2026-08-12T18:00:00Z",
    }


class AuthorityGateTests(unittest.TestCase):
    def test_in_scope_allowed(self):
        self.assertEqual(gate.evaluate(policy(), request(), NOW)["decision"], "ALLOW")

    def test_target_expansion_requires_escalation(self):
        r = request(); r["target"] = "external://b"
        receipt = gate.evaluate(policy(), r, NOW)
        self.assertEqual(receipt["decision"], "ESCALATE")
        self.assertEqual(receipt["reason"], "target_scope")

    def test_ambient_credential_denied(self):
        r = request(); r["credential_ref"] = "admin-token"
        receipt = gate.evaluate(policy(), r, NOW)
        self.assertEqual(receipt["decision"], "DENY")
        self.assertEqual(receipt["reason"], "credential_scope")

    def test_side_effect_ceiling_denied(self):
        r = request(); r["side_effect"] = "persistent_write"
        self.assertEqual(gate.evaluate(policy(), r, NOW)["decision"], "DENY")

    def test_budget_overrun_denied(self):
        r = request(); r["usage"]["network_calls"] = 3
        self.assertEqual(gate.evaluate(policy(), r, NOW)["decision"], "DENY")

    def test_expired_policy_denied(self):
        p = policy(); p["expires_at"] = "2026-08-11T00:00:00Z"
        self.assertEqual(gate.evaluate(p, request(), NOW)["decision"], "DENY")

    def test_malformed_request_fails_closed(self):
        r = request(); del r["usage"]
        self.assertEqual(gate.evaluate(policy(), r, NOW)["decision"], "DENY")


if __name__ == "__main__":
    unittest.main()
