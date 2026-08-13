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

CAP_READ = "cap-sha256:" + "1" * 64
CAP_LIST = "cap-sha256:" + "2" * 64
CAP_ADMIN = "cap-sha256:" + "3" * 64


def parent_policy():
    return {
        "policy_id": "PARENT",
        "principal": "orchestrator",
        "objectives": ["audit", "summarize"],
        "operations": ["read", "list"],
        "targets": ["repo://amas", "sandbox://artifact"],
        "destinations": ["api://github"],
        "credentials": ["github-read"],
        "capability_contracts": [CAP_READ, CAP_LIST],
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


def child_policy(parent=None):
    parent = parent or parent_policy()
    return {
        "policy_id": "CHILD",
        "parent_policy_id": parent["policy_id"],
        "parent_policy_hash": delegation.canonical_policy_hash(parent),
        "principal": "worker",
        "objectives": ["audit"],
        "operations": ["read"],
        "targets": ["repo://amas"],
        "destinations": ["api://github"],
        "credentials": ["github-read"],
        "capability_contracts": [CAP_READ],
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
        parent = parent_policy()
        self.assertTrue(delegation.verify_child_policy(parent, child_policy(parent))["valid"])

    def test_parent_hash_binding_denies_reused_parent_id_with_changed_authority(self):
        parent = parent_policy()
        child = child_policy(parent)
        mutated = parent_policy()
        mutated["targets"].append("external://new")
        result = delegation.verify_child_policy(mutated, child)
        self.assertFalse(result["valid"])
        self.assertEqual(result["reason"], "parent_hash_binding")

    def test_target_widening_denied(self):
        p = parent_policy(); c = child_policy(p); c["targets"].append("external://prod")
        result = delegation.verify_child_policy(p, c)
        self.assertFalse(result["valid"])
        self.assertEqual(result["reason"], "subset:targets")

    def test_credential_widening_denied(self):
        p = parent_policy(); c = child_policy(p); c["credentials"].append("admin-token")
        self.assertFalse(delegation.verify_child_policy(p, c)["valid"])

    def test_capability_contract_widening_denied(self):
        p = parent_policy(); c = child_policy(p); c["capability_contracts"].append(CAP_ADMIN)
        result = delegation.verify_child_policy(p, c)
        self.assertFalse(result["valid"])
        self.assertEqual(result["reason"], "subset:capability_contracts")

    def test_budget_widening_denied(self):
        p = parent_policy(); c = child_policy(p); c["budgets"]["max_actions"] = 101
        self.assertFalse(delegation.verify_child_policy(p, c)["valid"])

    def test_expiry_widening_denied(self):
        p = parent_policy(); c = child_policy(p); c["expires_at"] = "2026-08-14T00:00:00Z"
        self.assertFalse(delegation.verify_child_policy(p, c)["valid"])

    def test_side_effect_widening_denied(self):
        p = parent_policy(); c = child_policy(p); c["max_side_effect"] = "persistent_write"
        self.assertFalse(delegation.verify_child_policy(p, c)["valid"])

    def test_depth_must_decrease(self):
        p = parent_policy(); c = child_policy(p); c["max_delegation_depth"] = 2
        self.assertFalse(delegation.verify_child_policy(p, c)["valid"])

    def test_parent_with_zero_depth_cannot_delegate(self):
        p = parent_policy(); p["max_delegation_depth"] = 0
        c = child_policy(p); c["max_delegation_depth"] = 0
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
