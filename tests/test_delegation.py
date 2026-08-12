import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(name, rel):
    spec = importlib.util.spec_from_file_location(name, ROOT / rel)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


delegation = load("delegation", "reference/delegation.py")
receipts = load("receipt_chain", "reference/receipt_chain.py")


def parent_policy():
    return {
        "policy_id": "PARENT",
        "principal": "orchestrator",
        "objectives": ["audit", "summarize"],
        "operations": ["read", "list"],
        "targets": ["repo://amas", "sandbox://artifact"],
        "destinations": ["api://github"],
        "credentials": ["github-read"],
        "max_side_effect": "reversible_write",
        "budgets": {
            "max_actions": 100,
            "max_network_calls": 50,
            "max_egress_bytes": 100000,
            "max_wall_clock_seconds": 600,
        },
        "max_delegation_depth": 2,
        "expires_at": "2026-08-13T00:00:00Z",
        "operator_escalation": True,
    }


def child_policy():
    return {
        "policy_id": "CHILD",
        "parent_policy_id": "PARENT",
        "principal": "worker",
        "objectives": ["audit"],
        "operations": ["read"],
        "targets": ["repo://amas"],
        "destinations": ["api://github"],
        "credentials": ["github-read"],
        "max_side_effect": "observe",
        "budgets": {
            "max_actions": 20,
            "max_network_calls": 10,
            "max_egress_bytes": 20000,
            "max_wall_clock_seconds": 120,
        },
        "max_delegation_depth": 1,
        "expires_at": "2026-08-12T23:00:00Z",
        "operator_escalation": False,
    }


class DelegationTests(unittest.TestCase):
    def test_valid_subset(self):
        self.assertTrue(delegation.verify_child_policy(parent_policy(), child_policy())["valid"])

    def test_target_widening_denied(self):
        c = child_policy(); c["targets"].append("external://prod")
        result = delegation.verify_child_policy(parent_policy(), c)
        self.assertFalse(result["valid"])
        self.assertEqual(result["reason"], "subset:targets")

    def test_credential_widening_denied(self):
        c = child_policy(); c["credentials"].append("admin-token")
        self.assertFalse(delegation.verify_child_policy(parent_policy(), c)["valid"])

    def test_budget_widening_denied(self):
        c = child_policy(); c["budgets"]["max_actions"] = 101
        self.assertFalse(delegation.verify_child_policy(parent_policy(), c)["valid"])

    def test_expiry_widening_denied(self):
        c = child_policy(); c["expires_at"] = "2026-08-14T00:00:00Z"
        self.assertFalse(delegation.verify_child_policy(parent_policy(), c)["valid"])

    def test_side_effect_widening_denied(self):
        c = child_policy(); c["max_side_effect"] = "persistent_write"
        self.assertFalse(delegation.verify_child_policy(parent_policy(), c)["valid"])

    def test_depth_must_decrease(self):
        c = child_policy(); c["max_delegation_depth"] = 2
        self.assertFalse(delegation.verify_child_policy(parent_policy(), c)["valid"])

    def test_parent_with_zero_depth_cannot_delegate(self):
        p = parent_policy(); p["max_delegation_depth"] = 0
        c = child_policy(); c["max_delegation_depth"] = 0
        self.assertFalse(delegation.verify_child_policy(p, c)["valid"])

    def test_derive_child_rejects_widening(self):
        with self.assertRaises(ValueError):
            delegation.derive_child_policy(
                parent_policy(), policy_id="C2", principal="worker",
                targets=["repo://amas", "external://prod"]
            )


class ReceiptChainTests(unittest.TestCase):
    def test_valid_chain(self):
        r0 = receipts.append_receipt({"decision": "ALLOW", "request_id": "R0"}, sequence=0)
        r1 = receipts.append_receipt({"decision": "DENY", "request_id": "R1"}, r0["receipt_hash"], 1)
        result = receipts.verify_chain([r0, r1])
        self.assertTrue(result["valid"])
        self.assertEqual(result["count"], 2)

    def test_mutation_detected(self):
        r0 = receipts.append_receipt({"decision": "ALLOW", "request_id": "R0"}, sequence=0)
        r0["decision"] = "DENY"
        self.assertFalse(receipts.verify_chain([r0])["valid"])

    def test_deletion_reordering_detected(self):
        r0 = receipts.append_receipt({"decision": "ALLOW", "request_id": "R0"}, sequence=0)
        r1 = receipts.append_receipt({"decision": "DENY", "request_id": "R1"}, r0["receipt_hash"], 1)
        self.assertFalse(receipts.verify_chain([r1, r0])["valid"])


if __name__ == "__main__":
    unittest.main()
