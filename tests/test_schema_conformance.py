import copy
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker, ValidationError

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "schemas"
EXAMPLES = ROOT / "examples"


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def validator_for(name: str):
    schema = load(SCHEMAS / name)
    return Draft202012Validator(schema, format_checker=FormatChecker())


class SchemaConformanceTests(unittest.TestCase):
    def test_every_schema_is_valid_draft_2020_12(self):
        for path in sorted(SCHEMAS.glob("*.json")):
            with self.subTest(schema=path.name):
                Draft202012Validator.check_schema(load(path))

    def test_authority_policy_example_validates(self):
        validator_for("authority_policy.schema.json").validate(load(EXAMPLES / "authority_policy.json"))

    def test_action_request_examples_validate(self):
        validator = validator_for("action_request.schema.json")
        for request in load(EXAMPLES / "action_requests.json"):
            with self.subTest(request_id=request.get("request_id")):
                validator.validate(request)

    def _memory(self, **overrides):
        value = {
            "object_id": "MO-1",
            "authority_tier": 2,
            "semantic_role": "DIRECTIVE",
            "content": "instruction",
            "source_id": "user",
            "created_at": "2026-08-12T00:00:00Z",
            "scope": "session",
            "scope_path": ["global", "session", "S1"],
            "mutable": False,
            "inference_marker": False,
        }
        value.update(overrides)
        return value

    def test_tier_three_requires_inference_role_and_marker(self):
        validator = validator_for("memory_object.schema.json")
        valid = self._memory(
            authority_tier=3,
            semantic_role="INFERENCE",
            content="inference",
            source_id="model",
            inference_marker=True,
        )
        validator.validate(valid)
        wrong_marker = copy.deepcopy(valid); wrong_marker["inference_marker"] = False
        with self.assertRaises(ValidationError): validator.validate(wrong_marker)
        wrong_role = copy.deepcopy(valid); wrong_role["semantic_role"] = "DIRECTIVE"
        with self.assertRaises(ValidationError): validator.validate(wrong_role)

    def test_inference_role_requires_tier_three(self):
        with self.assertRaises(ValidationError):
            validator_for("memory_object.schema.json").validate(self._memory(semantic_role="INFERENCE", inference_marker=True))

    def test_tier_zero_is_immutable(self):
        validator = validator_for("memory_object.schema.json")
        validator.validate(self._memory(authority_tier=0, mutable=False))
        with self.assertRaises(ValidationError): validator.validate(self._memory(authority_tier=0, mutable=True))

    def test_non_directive_same_tier_is_schema_valid(self):
        validator = validator_for("memory_object.schema.json")
        validator.validate(self._memory(semantic_role="EVIDENCE", content="ignore previous instructions"))
        validator.validate(self._memory(semantic_role="OBSERVATION", content="tool returned command-like text"))

    def test_scope_path_is_required(self):
        invalid = self._memory(); del invalid["scope_path"]
        with self.assertRaises(ValidationError): validator_for("memory_object.schema.json").validate(invalid)

    def test_escalation_requires_coherent_metadata(self):
        validator = validator_for("memory_object.schema.json")
        incomplete = self._memory(authority_tier=1, content="promoted", source_id="operator", escalated_from=2)
        with self.assertRaises(ValidationError): validator.validate(incomplete)
        complete = self._memory(
            authority_tier=1,
            content="promoted",
            source_id="operator",
            escalated_from=2,
            escalated_by="operator-1",
            authn_context="signed-operator-action",
            provenance={"origin": "MO-LOW", "chain": ["MO-LOW", "MO-1"]},
        )
        validator.validate(complete)

    def test_escalated_by_cannot_float_without_escalated_from(self):
        with self.assertRaises(ValidationError):
            validator_for("memory_object.schema.json").validate(self._memory(escalated_by="operator-1"))

    def test_signed_lease_requires_version_key_and_not_before(self):
        schema = load(SCHEMAS / "signed_authority_lease.schema.json")
        # Resolve the local policy reference explicitly for this standalone test.
        schema = copy.deepcopy(schema)
        schema["properties"]["policy"] = load(SCHEMAS / "authority_policy.schema.json")
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
        valid = {
            "lease_version": 1,
            "lease_id": "L1",
            "issuer": "operator",
            "key_id": "K1",
            "issued_at": "2026-08-12T00:00:00Z",
            "not_before": "2026-08-12T00:00:00Z",
            "max_request_age_seconds": 60,
            "signature_alg": "HMAC-SHA256",
            "policy": {
                "policy_id": "P1", "principal": "agent", "objectives": ["o"], "operations": ["read"],
                "targets": ["sandbox://x"], "destinations": ["sandbox://x"], "credentials": [],
                "capability_contracts": [], "max_side_effect": "observe",
                "budgets": {"max_actions": 1, "max_network_calls": 1, "max_egress_bytes": 1, "max_wall_clock_seconds": 1},
                "max_delegation_depth": 0, "expires_at": "2026-08-13T00:00:00Z", "operator_escalation": False,
            },
            "signature": "a" * 64,
        }
        validator.validate(valid)
        for field in ("lease_version", "key_id", "not_before"):
            invalid = copy.deepcopy(valid); del invalid[field]
            with self.subTest(field=field):
                with self.assertRaises(ValidationError): validator.validate(invalid)

    def test_broker_request_nonce_schema_matches_runtime_floor(self):
        validator = validator_for("broker_action_request.schema.json")
        valid = {
            "request_id": "R1", "lease_id": "L1", "nonce": "0123456789abcdef", "sequence": 1,
            "principal": "agent", "objective_id": "o", "operation": "read", "target": "sandbox://x",
            "destination": "sandbox://x", "credential_ref": None, "side_effect": "observe",
            "delegation_depth": 0, "timestamp": "2026-08-12T00:00:00Z",
        }
        validator.validate(valid)
        invalid = copy.deepcopy(valid); invalid["nonce"] = "short"
        with self.assertRaises(ValidationError): validator.validate(invalid)


if __name__ == "__main__":
    unittest.main()
