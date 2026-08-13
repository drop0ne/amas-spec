import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = ROOT / "reference"
sys.path.insert(0, str(REFERENCE))

from delegation import derive_child_policy, verify_child_policy
from enforcement_broker import EnforcementBroker, sign_lease

KEY = b"policy-admission-test-key"


def policy():
    return {
        "policy_id": "P1", "principal": "agent", "objectives": ["inspect"], "operations": ["read"],
        "targets": ["sandbox://data"], "destinations": ["sandbox://data"], "credentials": [], "capability_contracts": [],
        "max_side_effect": "observe",
        "budgets": {"max_actions": 10, "max_network_calls": 10, "max_egress_bytes": 1000, "max_wall_clock_seconds": 60},
        "max_delegation_depth": 1, "expires_at": "2026-08-14T00:00:00Z", "operator_escalation": False,
    }


def lease():
    value = {
        "lease_version": 1, "lease_id": "L1", "issuer": "operator", "key_id": "K1",
        "issued_at": "2026-08-13T00:00:00Z", "not_before": "2026-08-13T00:00:00Z",
        "max_request_age_seconds": 60, "signature_alg": "HMAC-SHA256", "policy": policy(),
    }
    value["signature"] = sign_lease(value, KEY)
    return value


class PolicyAdmissionHardeningTests(unittest.TestCase):
    def test_signed_lease_with_unknown_envelope_field_is_rejected(self):
        value = lease()
        value["unexpected"] = "still signed"
        value["signature"] = sign_lease(value, KEY)
        with self.assertRaises(ValueError):
            EnforcementBroker(value, KEY)

    def test_child_with_unknown_field_is_not_authorized_subset(self):
        parent = policy()
        child = derive_child_policy(parent, policy_id="C1", principal="child")
        child["unexpected"] = "x"
        result = verify_child_policy(parent, child)
        self.assertFalse(result["valid"])
        self.assertTrue(result["reason"].startswith("invalid_policy:"))

    def test_unknown_child_override_is_rejected(self):
        with self.assertRaises(ValueError):
            derive_child_policy(policy(), policy_id="C1", principal="child", unexpected="x")

    def test_partial_parent_binding_is_rejected(self):
        malformed = copy.deepcopy(policy())
        malformed["parent_policy_id"] = "P0"
        result = verify_child_policy(policy(), malformed)
        self.assertFalse(result["valid"])


if __name__ == "__main__":
    unittest.main()
