import itertools
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = ROOT / "reference"
sys.path.insert(0, str(REFERENCE))

from conflict_resolution import resolve_pair, resolve_set
from delegation import canonical_policy_hash, verify_child_policy

CAP_A = "cap-sha256:" + "1" * 64
CAP_B = "cap-sha256:" + "2" * 64


def mo(object_id, *, tier=2, role="DIRECTIVE", created="2026-08-14T20:00:00Z", scope_path=None):
    return {
        "object_id": object_id,
        "authority_tier": tier,
        "semantic_role": role,
        "content": object_id,
        "source_id": "generated-test",
        "created_at": created,
        "scope": "generated",
        "scope_path": scope_path or ["global", "session", "S1"],
        "mutable": False,
        "inference_marker": role == "INFERENCE",
    }


def parent_policy():
    return {
        "policy_id": "PARENT-GEN", "principal": "orchestrator",
        "objectives": ["audit", "summarize"], "operations": ["read", "list"],
        "targets": ["repo://amas", "sandbox://artifact"], "destinations": ["api://github", "mock://local"],
        "credentials": ["github-read", "mock-read"], "capability_contracts": [CAP_A, CAP_B],
        "max_side_effect": "reversible_write",
        "budgets": {"max_actions": 8, "max_network_calls": 6, "max_egress_bytes": 1000, "max_wall_clock_seconds": 60},
        "max_delegation_depth": 2, "expires_at": "2026-08-15T00:00:00Z", "operator_escalation": True,
    }


def child_from(parent):
    return {
        "policy_id": "CHILD-GEN", "parent_policy_id": parent["policy_id"],
        "parent_policy_hash": canonical_policy_hash(parent), "principal": "worker",
        "objectives": list(parent["objectives"]), "operations": list(parent["operations"]),
        "targets": list(parent["targets"]), "destinations": list(parent["destinations"]),
        "credentials": list(parent["credentials"]), "capability_contracts": list(parent["capability_contracts"]),
        "max_side_effect": "observe", "budgets": dict(parent["budgets"]), "max_delegation_depth": 1,
        "expires_at": "2026-08-14T23:00:00Z", "operator_escalation": False,
    }


class GeneratedAMASProperties(unittest.TestCase):
    def test_pair_order_invariance_across_tier_scope_and_recency(self):
        tiers = [0, 1, 2]
        times = ["2026-08-14T20:00:00Z", "2026-08-14T21:00:00Z"]
        scopes = [["global"], ["global", "session"], ["global", "other"]]
        counter = 0
        for tier_a, tier_b, time_a, time_b, scope_a, scope_b in itertools.product(tiers, tiers, times, times, scopes, scopes):
            counter += 1
            a = mo(f"A{counter}", tier=tier_a, created=time_a, scope_path=scope_a)
            b = mo(f"B{counter}", tier=tier_b, created=time_b, scope_path=scope_b)
            ab = resolve_pair(a, b)
            ba = resolve_pair(b, a)
            self.assertEqual(ab["decision"], ba["decision"])
            self.assertEqual(ab.get("winner"), ba.get("winner"))
            self.assertEqual(ab["rule"], ba["rule"])

    def test_non_directives_never_defeat_directive_authority(self):
        for role in ("EVIDENCE", "OBSERVATION"):
            for tier in (0, 1, 2):
                directive = mo(f"D-{role}-{tier}", tier=tier, role="DIRECTIVE")
                data = mo(f"N-{role}-{tier}", tier=tier, role=role, created="2026-08-14T22:00:00Z")
                result = resolve_pair(directive, data)
                self.assertEqual(result["decision"], "RESOLVED")
                self.assertEqual(result["winner"], directive["object_id"])
                self.assertEqual(result["rule"], "semantic_role_admissibility")

    def test_resolve_set_is_permutation_invariant_when_unique_dominator_exists(self):
        objects = [
            mo("CANON", tier=0, scope_path=["global"]),
            mo("SESSION-OLD", tier=2, created="2026-08-14T20:00:00Z"),
            mo("SESSION-NEW", tier=2, created="2026-08-14T21:00:00Z"),
        ]
        outcomes = {(resolve_set(list(order))["decision"], resolve_set(list(order))["winner"]) for order in itertools.permutations(objects)}
        self.assertEqual(outcomes, {("RESOLVED", "CANON")})


class GeneratedDelegationProperties(unittest.TestCase):
    def test_every_generated_subset_is_valid_and_outsider_widens(self):
        set_fields = ("objectives", "operations", "targets", "destinations", "credentials", "capability_contracts")
        for field in set_fields:
            parent = parent_policy()
            values = parent[field]
            for size in range(len(values) + 1):
                for subset in itertools.combinations(values, size):
                    child = child_from(parent)
                    child[field] = list(subset)
                    self.assertTrue(verify_child_policy(parent, child)["valid"], (field, subset))
            child = child_from(parent)
            outsider = "cap-sha256:" + "f" * 64 if field == "capability_contracts" else "outside://authority"
            child[field] = list(values) + [outsider]
            self.assertFalse(verify_child_policy(parent, child)["valid"], field)

    def test_budget_monotonicity_generated(self):
        for budget_field in ("max_actions", "max_network_calls", "max_egress_bytes", "max_wall_clock_seconds"):
            parent = parent_policy()
            parent_value = parent["budgets"][budget_field]
            for child_value in (0, max(parent_value - 1, 0), parent_value):
                child = child_from(parent)
                child["budgets"][budget_field] = child_value
                self.assertTrue(verify_child_policy(parent, child)["valid"], (budget_field, child_value))
            child = child_from(parent)
            child["budgets"][budget_field] = parent_value + 1
            self.assertFalse(verify_child_policy(parent, child)["valid"], budget_field)


if __name__ == "__main__":
    unittest.main()
