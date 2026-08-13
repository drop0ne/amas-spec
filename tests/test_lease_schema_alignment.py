import json
import sys
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = ROOT / "reference"
SCHEMAS = ROOT / "schemas"
sys.path.insert(0, str(REFERENCE))

from delegation import derive_child_policy
from enforcement_broker import sign_lease

KEY = b"schema-alignment-reference-key"
CAP_ID = "cap-sha256:" + "a" * 64


def load_schema(name):
    return json.loads((SCHEMAS / name).read_text(encoding="utf-8"))


def local_registry():
    registry = Registry()
    for path in sorted(SCHEMAS.glob("*.json")):
        schema = json.loads(path.read_text(encoding="utf-8"))
        schema_id = schema.get("$id")
        if isinstance(schema_id, str):
            registry = registry.with_resource(schema_id, Resource.from_contents(schema))
    return registry


REGISTRY = local_registry()


def parent_policy():
    return {
        "policy_id": "PARENT",
        "principal": "agent-parent",
        "objectives": ["inspect"],
        "operations": ["read"],
        "targets": ["sandbox://x"],
        "destinations": ["sandbox://x"],
        "credentials": ["read-token"],
        "capability_contracts": [CAP_ID],
        "max_side_effect": "observe",
        "budgets": {
            "max_actions": 10,
            "max_network_calls": 5,
            "max_egress_bytes": 1000,
            "max_wall_clock_seconds": 60,
        },
        "max_delegation_depth": 1,
        "expires_at": "2026-08-13T00:00:00Z",
        "operator_escalation": False,
    }


def signed_lease(policy, *, lease_id="LEASE-1"):
    value = {
        "lease_version": 1,
        "lease_id": lease_id,
        "issuer": "operator-root",
        "key_id": "test-key-1",
        "issued_at": "2026-08-12T22:00:00Z",
        "not_before": "2026-08-12T22:00:00Z",
        "max_request_age_seconds": 300,
        "signature_alg": "HMAC-SHA256",
        "policy": policy,
    }
    value["signature"] = sign_lease(value, KEY)
    return value


class LeaseSchemaAlignmentTests(unittest.TestCase):
    def validate(self, schema_name, instance):
        Draft202012Validator(
            load_schema(schema_name),
            registry=REGISTRY,
            format_checker=FormatChecker(),
        ).validate(instance)

    def test_parent_policy_and_signed_lease_validate(self):
        policy = parent_policy()
        self.validate("authority_policy.schema.json", policy)
        self.validate("signed_authority_lease.schema.json", signed_lease(policy))

    def test_derived_child_and_signed_child_lease_validate(self):
        parent = parent_policy()
        child = derive_child_policy(
            parent,
            policy_id="CHILD",
            principal="agent-child",
            objectives=["inspect"],
            operations=["read"],
            targets=["sandbox://x"],
            destinations=["sandbox://x"],
            credentials=["read-token"],
            capability_contracts=[CAP_ID],
            max_delegation_depth=0,
            expires_at="2026-08-12T23:00:00Z",
        )
        self.validate("child_authority_policy.schema.json", child)
        self.validate("signed_child_authority_lease.schema.json", signed_lease(child, lease_id="LEASE-CHILD"))


if __name__ == "__main__":
    unittest.main()
