import json
import unittest
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "schemas"


def walk_refs(value):
    if isinstance(value, dict):
        if isinstance(value.get("$ref"), str):
            yield value["$ref"]
        for child in value.values():
            yield from walk_refs(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk_refs(child)


class SchemaReferenceIntegrityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.by_path = {}
        cls.by_id = {}
        for path in sorted(SCHEMAS.glob("*.json")):
            value = json.loads(path.read_text(encoding="utf-8"))
            cls.by_path[path.name] = value
            schema_id = value.get("$id")
            if isinstance(schema_id, str):
                if schema_id in cls.by_id:
                    raise AssertionError(f"duplicate schema $id: {schema_id}")
                cls.by_id[schema_id] = path.name

    def test_every_schema_has_unique_absolute_id(self):
        for name, schema in self.by_path.items():
            with self.subTest(schema=name):
                schema_id = schema.get("$id")
                self.assertIsInstance(schema_id, str)
                parsed = urlparse(schema_id)
                self.assertIn(parsed.scheme, {"https", "http"})
                self.assertTrue(parsed.netloc)

    def test_every_local_reference_resolves_without_network_discovery(self):
        for name, schema in self.by_path.items():
            for ref in walk_refs(schema):
                with self.subTest(schema=name, ref=ref):
                    if ref.startswith("#"):
                        continue
                    parsed = urlparse(ref)
                    if parsed.scheme:
                        target = ref.split("#", 1)[0]
                        self.assertIn(target, self.by_id, f"unresolved absolute schema ref: {ref}")
                    else:
                        target = ref.split("#", 1)[0]
                        self.assertIn(Path(target).name, self.by_path, f"unresolved relative schema ref: {ref}")


if __name__ == "__main__":
    unittest.main()
