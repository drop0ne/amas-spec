import math
import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = ROOT / "reference"
sys.path.insert(0, str(REFERENCE))

import authority_gate
import capability_contract
import enforcement_broker
from mediated_executor import ExecutionBindingError, PreparedAction

NOW = datetime(2026, 8, 12, 22, 30, tzinfo=timezone.utc)
KEY = b"strict-json-test-key"


def policy():
    return {
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
        "policy": policy(),
    }
    value["signature"] = enforcement_broker.sign_lease(value, KEY)
    return value


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


def contract_body(parameter, values):
    return {
        "adapter_id": "mock",
        "operation": "read",
        "allowed_parameter_keys": [parameter],
        "required_parameter_keys": [parameter],
        "unrestricted_parameter_keys": [],
        "parameter_allowlists": {parameter: values},
        "allowed_effective_destinations": ["sandbox://x"],
        "allowed_credentials": [],
        "allow_redirects": False,
        "allowed_filesystem_paths": [],
        "allow_subprocess": False,
        "allowed_subprocesses": [],
        "allowed_secondary_destinations": [],
    }


class StrictJsonSecurityTests(unittest.TestCase):
    def test_authority_gate_rejects_nan(self):
        request = {
            "request_id": "R1",
            "principal": "agent",
            "objective_id": "obj",
            "operation": "read",
            "target": "sandbox://x",
            "destination": "sandbox://x",
            "credential_ref": None,
            "side_effect": "observe",
            "usage": {
                "actions": 1,
                "network_calls": 0,
                "egress_bytes": 0,
                "wall_clock_seconds": math.nan,
            },
            "delegation_depth": 0,
        }
        receipt = authority_gate.evaluate(policy(), request, NOW)
        self.assertEqual(receipt["decision"], "DENY")
        self.assertTrue(receipt["reason"].startswith("invalid_request:"))
        self.assertEqual(len(receipt["request_hash"]), 64)

    def test_reference_hmac_key_cannot_be_empty(self):
        unsigned = lease()
        unsigned.pop("signature", None)
        with self.assertRaises(ValueError):
            enforcement_broker.sign_lease(unsigned, b"")

    def test_revocation_checker_exception_fails_closed(self):
        def broken(_lease_id):
            raise RuntimeError("revocation service unavailable")

        broker = enforcement_broker.EnforcementBroker(lease(), KEY, revocation_checker=broken)
        receipt = broker.authorize(
            broker_request(),
            cost={"actions": 1, "network_calls": 0, "egress_bytes": 0, "wall_clock_seconds": 1},
            now=NOW,
        )
        self.assertEqual(receipt["decision"], "DENY")
        self.assertEqual(receipt["reason"], "revocation_check_failed:RuntimeError")
        self.assertTrue(broker.verify_receipts())

    def test_revocation_checker_non_boolean_fails_closed(self):
        broker = enforcement_broker.EnforcementBroker(lease(), KEY, revocation_checker=lambda _lease_id: "no")
        receipt = broker.authorize(
            broker_request(),
            cost={"actions": 1, "network_calls": 0, "egress_bytes": 0, "wall_clock_seconds": 1},
            now=NOW,
        )
        self.assertEqual(receipt["decision"], "DENY")
        self.assertEqual(receipt["reason"], "revocation_check_failed:TypeError")

    def test_broker_rejects_hidden_nan_and_keeps_receipt_chain_valid(self):
        broker = enforcement_broker.EnforcementBroker(lease(), KEY)
        request = broker_request()
        request["hidden"] = math.nan
        receipt = broker.authorize(
            request,
            cost={"actions": 1, "network_calls": 0, "egress_bytes": 0, "wall_clock_seconds": 1},
            now=NOW,
        )
        self.assertEqual(receipt["decision"], "DENY")
        self.assertTrue(receipt["reason"].startswith("invalid_envelope:"))
        self.assertTrue(broker.verify_receipts())

    def test_capability_allowlist_does_not_conflate_boolean_and_integer(self):
        contract = capability_contract.bind_contract_id(contract_body("flag", [1]))
        result = capability_contract.validate_contract(
            contract,
            adapter_id="mock",
            broker_request={"operation": "read", "destination": "sandbox://x", "credential_ref": None},
            parameters={"flag": True},
            security_effects=None,
        )
        self.assertFalse(result["valid"])
        self.assertEqual(result["reason"], "contract_parameter_value:flag")

    def test_capability_contract_rejects_nan_allowlist_value(self):
        with self.assertRaises(ValueError):
            capability_contract.bind_contract_id(contract_body("value", [math.nan]))

    def test_prepared_action_rejects_nan_parameter(self):
        with self.assertRaises(ExecutionBindingError):
            PreparedAction(
                adapter_id="mock",
                broker_request=broker_request(),
                parameters={"value": math.nan},
                cost={"actions": 1, "network_calls": 0, "egress_bytes": 0, "wall_clock_seconds": 1},
            )


if __name__ == "__main__":
    unittest.main()
