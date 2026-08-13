import json
import sys
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker, ValidationError

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = ROOT / "reference"
SCHEMAS = ROOT / "schemas"
sys.path.insert(0, str(REFERENCE))

from capability_contract import bind_contract_id, verify_contract_identity


def schema(name):
    return json.loads((SCHEMAS / name).read_text(encoding="utf-8"))


def contract():
    return bind_contract_id({
        "adapter_id": "mock",
        "operation": "read",
        "allowed_parameter_keys": ["path", "query"],
        "required_parameter_keys": ["path"],
        "unrestricted_parameter_keys": ["query"],
        "parameter_allowlists": {"path": ["/record"]},
        "allowed_effective_destinations": ["sandbox://x"],
        "allowed_credentials": ["read-token"],
        "allow_redirects": False,
        "allowed_filesystem_paths": [],
        "allow_subprocess": False,
        "allowed_subprocesses": [],
        "allowed_secondary_destinations": [],
    })


class CapabilityContractSchemaTests(unittest.TestCase):
    def test_content_addressed_contract_validates(self):
        value = contract()
        Draft202012Validator(schema("capability_contract.schema.json"), format_checker=FormatChecker()).validate(value)
        self.assertTrue(verify_contract_identity(value))

    def test_mutated_contract_no_longer_matches_identity(self):
        value = contract()
        value["allow_redirects"] = True
        self.assertFalse(verify_contract_identity(value))

    def test_authority_policy_accepts_only_content_addressed_contract_ids(self):
        validator = Draft202012Validator(schema("authority_policy.schema.json"), format_checker=FormatChecker())
        base = {
            "policy_id": "P1",
            "principal": "agent",
            "objectives": ["obj"],
            "operations": ["read"],
            "targets": ["sandbox://x"],
            "destinations": ["sandbox://x"],
            "credentials": ["read-token"],
            "capability_contracts": [contract()["contract_id"]],
            "max_side_effect": "observe",
            "budgets": {"max_actions": 1, "max_network_calls": 1, "max_egress_bytes": 1, "max_wall_clock_seconds": 1},
            "max_delegation_depth": 1,
            "expires_at": "2026-08-13T00:00:00Z",
            "operator_escalation": False,
        }
        validator.validate(base)
        invalid = dict(base); invalid["capability_contracts"] = ["CAP-READ"]
        with self.assertRaises(ValidationError): validator.validate(invalid)

    def test_broker_request_contract_id_pattern(self):
        validator = Draft202012Validator(schema("broker_action_request.schema.json"), format_checker=FormatChecker())
        request = {
            "request_id": "R1", "lease_id": "L1", "nonce": "0123456789abcdef", "sequence": 1,
            "principal": "agent", "objective_id": "obj", "operation": "read", "target": "sandbox://x",
            "destination": "sandbox://x", "credential_ref": "read-token",
            "capability_contract_id": contract()["contract_id"],
            "side_effect": "observe", "delegation_depth": 0, "timestamp": "2026-08-12T22:00:00Z",
        }
        validator.validate(request)
        request["capability_contract_id"] = "human-readable-name"
        with self.assertRaises(ValidationError): validator.validate(request)


if __name__ == "__main__":
    unittest.main()
