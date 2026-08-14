import json
from pathlib import Path
import unittest

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

from evaluation.mediated_agent.harness import MediatedHarness, SyntheticAuthority

ROOT = Path(__file__).resolve().parents[1]


class EvaluationFoundationTests(unittest.TestCase):
    def setUp(self):
        self.authority = SyntheticAuthority(
            operations={"read", "write"},
            targets={"report"},
            destinations={"mock://allowed"},
        )
        self.harness = MediatedHarness(self.authority)

    def test_authorized_effect_executes_once(self):
        decision, result = self.harness.submit({
            "operation": "write",
            "target": "report",
            "destination": "mock://allowed",
            "parameters": {},
        })
        self.assertTrue(decision.allowed)
        self.assertIsNotNone(result)
        self.assertEqual(len(self.harness.evidence()["effects"]), 1)
        self.assertEqual(result["action_hash"], decision.action_hash)

    def test_forbidden_destination_has_no_effect(self):
        decision, result = self.harness.submit({
            "operation": "write",
            "target": "report",
            "destination": "mock://forbidden",
            "parameters": {},
        })
        self.assertFalse(decision.allowed)
        self.assertIsNone(result)
        self.assertEqual(self.harness.evidence()["effects"], [])

    def test_redirect_is_authorized_by_effective_destination(self):
        decision, _ = self.harness.submit({
            "operation": "write",
            "target": "report",
            "destination": "mock://allowed",
            "parameters": {"redirect_to": "mock://forbidden"},
        })
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "destination_out_of_scope")
        self.assertEqual(self.harness.evidence()["effects"], [])

    def test_secondary_effect_is_separately_scoped(self):
        decision, _ = self.harness.submit({
            "operation": "write",
            "target": "report",
            "destination": "mock://allowed",
            "parameters": {"secondary_destination": "mock://forbidden"},
        })
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason, "secondary_destination_out_of_scope")
        self.assertEqual(self.harness.evidence()["effects"], [])

    def test_e0_corpus_expectations(self):
        corpus = json.loads((ROOT / "evaluation" / "corpora" / "e0_basic.json").read_text(encoding="utf-8"))
        for case in corpus:
            harness = MediatedHarness(self.authority)
            decision, _ = harness.submit(case["proposal"])
            self.assertEqual("ALLOW" if decision.allowed else "DENY", case["expect"], case["task_id"])

    def test_evaluation_schemas_are_closed_and_valid(self):
        resources = []
        schemas = {}
        for path in sorted((ROOT / "evaluation" / "schemas").glob("*.schema.json")):
            schema = json.loads(path.read_text(encoding="utf-8"))
            Draft202012Validator.check_schema(schema)
            schemas[path.name] = schema
            resources.append((schema["$id"], Resource.from_contents(schema)))
            resources.append((path.name, Resource.from_contents(schema)))
            self.assertFalse(schema.get("additionalProperties", True), path.name)
        registry = Registry().with_resources(resources)
        environment = {
            "environment_id": "test",
            "topology": "caller -> mediator -> mock",
            "trusted_components": ["mediator"],
            "effect_surfaces": ["mock.write"],
            "hidden_configuration_hash": "0" * 64,
        }
        Draft202012Validator(
            schemas["evaluation_environment.schema.json"],
            registry=registry,
            format_checker=FormatChecker(),
        ).validate(environment)


if __name__ == "__main__":
    unittest.main()
