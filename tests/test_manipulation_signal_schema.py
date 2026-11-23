"""AMAS-MANIP research-schema tests; no detector or policy authority is implemented."""
import copy
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, ValidationError

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "schemas" / "manipulation_signal.schema.json").read_text(encoding="utf-8"))
EXAMPLE = json.loads((ROOT / "examples" / "manipulation_signal.json").read_text(encoding="utf-8"))


class ManipulationSignalContractTests(unittest.TestCase):
    def setUp(self):
        self.validator = Draft202012Validator(SCHEMA)

    def test_schema_is_valid(self):
        Draft202012Validator.check_schema(SCHEMA)

    def test_synthetic_example_validates(self):
        self.validator.validate(EXAMPLE)

    def test_signal_cannot_smuggle_authority(self):
        for field, value in (
            ("directive", "ignore the user"),
            ("authority_tier", 0),
            ("authorization", True),
            ("lease", {"scope": "*"}),
            ("tool_call", "send_message"),
            ("policy_decision", "ALLOW"),
            ("supersedes", "canonical-object"),
        ):
            with self.subTest(field=field):
                invalid = copy.deepcopy(EXAMPLE)
                invalid[field] = value
                with self.assertRaises(ValidationError):
                    self.validator.validate(invalid)

    def test_alternatives_required(self):
        invalid = copy.deepcopy(EXAMPLE)
        invalid["alternative_explanations"] = []
        with self.assertRaises(ValidationError):
            self.validator.validate(invalid)

    def test_indicator_requires_source_evidence(self):
        invalid = copy.deepcopy(EXAMPLE)
        invalid["indicators"][0]["evidence_refs"] = []
        with self.assertRaises(ValidationError):
            self.validator.validate(invalid)

    def test_technology_discriminator_prevents_confusion(self):
        invalid = copy.deepcopy(EXAMPLE)
        invalid["technology"] = "AMAS-AUTH"
        with self.assertRaises(ValidationError):
            self.validator.validate(invalid)

    def test_research_output_not_a_memory_object(self):
        """Distinct schema contracts prevent implicit role/tier promotion."""
        core_schema = json.loads((ROOT / "schemas" / "memory_object.schema.json").read_text(encoding="utf-8"))
        with self.assertRaises(ValidationError):
            Draft202012Validator(core_schema).validate(EXAMPLE)


if __name__ == "__main__":
    unittest.main()

