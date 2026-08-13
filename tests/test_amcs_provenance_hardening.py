import argparse
import json
import sys
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = ROOT / "reference"
SCHEMAS = ROOT / "schemas"
sys.path.insert(0, str(REFERENCE))

import amcs


class AMCSProvenanceHardeningTests(unittest.TestCase):
    def _chat(self, root: Path) -> Path:
        path = root / "chat.json"
        path.write_text(json.dumps([
            {"role": "user", "content": "inspect this"},
            {"role": "assistant", "content": "inspected"},
        ]), encoding="utf-8")
        return path

    def _args(self, root: Path, **overrides):
        values = {
            "input": str(self._chat(root)),
            "out_dir": str(root / "out"),
            "cell_name": "CELL_PROV",
            "scope": "entire_chat",
            "primary_narrative_source": "chat",
            "odt": None,
            "attachments_root": None,
            "genesis_prompt": None,
            "parse_session_header": True,
            "parent_cell": None,
            "parent_seal_key_hex": None,
            "delta_type": None,
            "case_study_id": None,
            "seal_key_hex": None,
            "max_archive_members": amcs.DEFAULT_MAX_ARCHIVE_MEMBERS,
            "max_expanded_bytes": amcs.DEFAULT_MAX_EXPANDED_BYTES,
        }
        values.update(overrides)
        return argparse.Namespace(**values)

    def _extract(self, archive: Path, root: Path) -> Path:
        dest = root / "extract"
        amcs.safe_extract_tar(archive, dest)
        return amcs._single_root(dest)

    def _validate(self, name: str, value):
        schema = json.loads((SCHEMAS / name).read_text(encoding="utf-8"))
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(value)

    def test_tensor_and_index_carry_direct_source_provenance(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = Path(amcs.seal(self._args(root)))
            cell = self._extract(archive, root)
            prompt_log = json.loads((cell / "data/prompt_log.json").read_text(encoding="utf-8"))
            tensor = json.loads((cell / "data/tensors/summary.json").read_text(encoding="utf-8"))
            index = json.loads((cell / "cell_index.json").read_text(encoding="utf-8"))

            prompt_ids = [entry["prompt_id"] for entry in prompt_log]
            hashes = [entry["message_hash"] for entry in prompt_log]
            self.assertEqual(tensor["source_prompt_ids"], prompt_ids)
            self.assertEqual(tensor["source_message_hashes"], hashes)
            self.assertEqual(len(tensor["source_response_ids"]), 1)
            self.assertEqual(index["source_prompt_ids"], prompt_ids)
            self.assertEqual(index["source_message_hashes"], hashes)
            self.assertEqual(len(index["source_response_ids"]), 1)

            self._validate("tensor_summary.schema.json", tensor)
            self._validate("cell_index.schema.json", index)
            ok, errors = amcs.verify_cell_dir(cell)
            self.assertTrue(ok, errors)

    def test_redundant_root_metadata_cannot_be_changed_even_if_root_hash_is_recomputed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = Path(amcs.seal(self._args(root)))
            cell = self._extract(archive, root)
            root_path = cell / "manifests/cell_root.json"
            record = json.loads(root_path.read_text(encoding="utf-8"))
            record["cell_id"] = "OTHER_CELL"
            payload_keys = (
                "root_version", "cell_id", "case_study_id", "content_manifest_hash",
                "seal_receipt_hash", "cell_index_hash", "parent_cell_hash", "delta_type",
                "authentication_alg",
            )
            payload = {key: record[key] for key in payload_keys}
            record["root_hash"] = amcs.canonical_hash(payload)
            root_path.write_text(json.dumps(record), encoding="utf-8")

            ok, errors = amcs.verify_cell_dir(cell)
            self.assertFalse(ok)
            self.assertTrue(any("cell_id metadata mismatch" in error for error in errors), errors)

    def test_index_provenance_tamper_breaks_root_binding(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = Path(amcs.seal(self._args(root)))
            cell = self._extract(archive, root)
            index_path = cell / "cell_index.json"
            index = json.loads(index_path.read_text(encoding="utf-8"))
            index["source_prompt_ids"] = list(reversed(index["source_prompt_ids"]))
            index_path.write_text(json.dumps(index), encoding="utf-8")
            ok, errors = amcs.verify_cell_dir(cell)
            self.assertFalse(ok)
            self.assertTrue(any("index binding mismatch" in error or "source_prompt_ids mismatch" in error for error in errors), errors)


if __name__ == "__main__":
    unittest.main()
