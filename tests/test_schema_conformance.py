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


class SchemaConformanceTests(unittest.TestCase):
    def test_every_schema_is_valid_draft_2020_12(self):
        for path in sorted(SCHEMAS.glob("*.json")):
            with self.subTest(schema=path.name):
                Draft202012Validator.check_schema(load(path))

    def test_authority_policy_example_validates(self):
        schema = load(SCHEMAS / "authority_policy.schema.json")
        instance = load(EXAMPLES / "authority_policy.json")
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(instance)

    def test_action_request_examples_validate(self):
        schema = load(SCHEMAS / "action_request.schema.json")
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
        for request in load(EXAMPLES / "action_requests.json"):
            with self.subTest(request_id=request.get("request_id")):
                validator.validate(request)

    def test_tier_three_requires_inference_marker(self):
        schema = load(SCHEMAS / "memory_object.schema.json")
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
        valid = {
            "object_id": "MO-1",
            "authority_tier": 3,
            "content": "inference",
            "source_id": "model",
            "created_at": "2026-08-12T00:00:00Z",
            "scope": "session",
            "mutable": False,
            "inference_marker": True,
        }
        validator.validate(valid)
        invalid = copy.deepcopy(valid)
        invalid["inference_marker"] = False
        with self.assertRaises(ValidationError):
            validator.validate(invalid)

    def test_escalation_requires_coherent_metadata(self):
        schema = load(SCHEMAS / "memory_object.schema.json")
        validator = Draft202012Validator(schema, format_checker=FormatChecker())
        incomplete = {
            "object_id": "MO-2",
            "authority_tier": 1,
            "content": "promoted",
            "source_id": "operator",
            "created_at": "2026-08-12T00:00:00Z",
            "scope": "session",
            "mutable": False,
            "inference_marker": False,
            "escalated_from": 2,
        }
        with self.assertRaises(ValidationError):
            validator.validate(incomplete)


if __name__ == "__main__":
    unittest.main()
