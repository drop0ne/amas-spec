import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = ROOT / "reference"
sys.path.insert(0, str(REFERENCE))

from capability_contract import bind_contract_id, validate_contract
from enforcement_broker import EnforcementBroker, sign_lease
from mediated_executor import ExecutionBindingError, PreparedAction

NOW = datetime(2026, 8, 12, 22, 30, tzinfo=timezone.utc)
KEY = b"canonical-numeric-policy-test"


def broker_request():
    return {
        "request_id": "R1",
        "lease_id": "L1",
        "nonce": "0123456789abcdef",
        "sequence": 1,
        "principal": "agent",
        "objective_id": "obj",
        "operation": "read",
        "target": "sandbox://x",
        "destination": "sandbox://x",
        "credential_ref": None,
        "side_effect": "observe",
        "delegation_depth": 0,
        "timestamp": "2026-08-12T22:30:00Z",
    }


def lease():
    value = {
        "lease_version": 1,
        "lease_id": "L1",
        "issuer": "operator",
        "key_id": "K1",
        "issued_at": "2026-08-12T22:00:00Z",
        "not_before": "2026-08-12T22:00:00Z",
        "max_request_age_seconds": 300,
        "signature_alg": "HMAC-SHA256",
        "policy": {
            "policy_id": "P1",
            "principal": "agent",
            "objectives": ["obj"],
            "operations": ["read"],
            "targets": ["sandbox://x"],
            "destinations": ["sandbox://x"],
            "credentials": [],
            "capability_contracts": [],
            "max_side_effect": "observe",
            "budgets": {
                "max_actions": 2,
                "max_network_calls": 1,
                "max_egress_bytes": 100,
                "max_wall_clock_seconds": 10,
            },
            "max_delegation_depth": 0,
            "expires_at": "2026-08-13T00:00:00Z",
            "operator_escalation": False,
        },
    }
    value["signature"] = sign_lease(value, KEY)
    return value


class CanonicalActionNumericPolicyTests(unittest.TestCase):
    def test_prepared_action_rejects_finite_float_parameter(self):
        with self.assertRaises(ExecutionBindingError):
            PreparedAction(
                adapter_id="mock",
                broker_request=broker_request(),
                parameters={"threshold": 0.5},
                cost={"actions": 1, "network_calls": 0, "egress_bytes": 0, "wall_clock_seconds": 1},
            )

    def test_capability_contract_rejects_float_allowlist(self):
        body = {
            "adapter_id": "mock",
            "operation": "read",
            "allowed_parameter_keys": ["threshold"],
            "required_parameter_keys": ["threshold"],
            "unrestricted_parameter_keys": [],
            "parameter_allowlists": {"threshold": [0.5]},
            "allowed_effective_destinations": ["sandbox://x"],
            "allowed_credentials": [],
            "allow_redirects": False,
            "allowed_filesystem_paths": [],
            "allow_subprocess": False,
            "allowed_subprocesses": [],
            "allowed_secondary_destinations": [],
        }
        with self.assertRaises(ValueError):
            bind_contract_id(body)

    def test_broker_rejects_float_hidden_in_request_and_chains_denial(self):
        broker = EnforcementBroker(lease(), KEY)
        request = broker_request()
        request["unexpected_float"] = 1.25
        receipt = broker.authorize(
            request,
            cost={"actions": 1, "network_calls": 0, "egress_bytes": 0, "wall_clock_seconds": 1},
            now=NOW,
        )
        self.assertEqual(receipt["decision"], "DENY")
        self.assertTrue(receipt["reason"].startswith("invalid_envelope:"))
        self.assertTrue(broker.verify_receipts())

    def test_integer_parameter_contract_remains_valid(self):
        contract = bind_contract_id({
            "adapter_id": "mock",
            "operation": "read",
            "allowed_parameter_keys": ["limit"],
            "required_parameter_keys": ["limit"],
            "unrestricted_parameter_keys": [],
            "parameter_allowlists": {"limit": [1, 2, 3]},
            "allowed_effective_destinations": ["sandbox://x"],
            "allowed_credentials": [],
            "allow_redirects": False,
            "allowed_filesystem_paths": [],
            "allow_subprocess": False,
            "allowed_subprocesses": [],
            "allowed_secondary_destinations": [],
        })
        result = validate_contract(
            contract,
            adapter_id="mock",
            broker_request={"operation": "read", "destination": "sandbox://x", "credential_ref": None},
            parameters={"limit": 2},
            security_effects=None,
        )
        self.assertTrue(result["valid"], result)


if __name__ == "__main__":
    unittest.main()
