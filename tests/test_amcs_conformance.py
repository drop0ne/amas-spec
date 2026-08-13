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


class AMCSConformanceTests(unittest.TestCase):
    def _chat(self, root: Path, messages=None) -> Path:
        path = root / "chat.json"
        path.write_text(json.dumps(messages or [
            {"role": "user", "content": "hello"},
            {"role": "assistant", "content": "world"},
        ]), encoding="utf-8")
        return path

    def _seal_args(self, root: Path, chat: Path, **overrides):
        values = {
            "input": str(chat), "out_dir": str(root / "out"), "cell_name": "CELL_1",
            "scope": "entire_chat", "primary_narrative_source": "chat", "odt": None,
            "attachments_root": None, "genesis_prompt": None, "parse_session_header": True,
            "parent_cell_hash": None, "delta_type": None, "case_study_id": None, "seal_key_hex": None,
        }
        values.update(overrides)
        return argparse.Namespace(**values)

    def _extract(self, archive: Path, root: Path, name="extract") -> Path:
        destination = root / name
        amcs.safe_extract_tar(archive, destination)
        return amcs._single_root(destination)

    def _validate(self, schema_name: str, instance):
        schema = json.loads((SCHEMAS / schema_name).read_text(encoding="utf-8"))
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(instance)

    def test_generated_cell_contains_required_v121_surfaces_and_validates(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = Path(amcs.seal(self._seal_args(root, self._chat(root))))
            cell = self._extract(archive, root)
            required = [
                "casefiles/CF_MESSAGES.md", "data/prompt_log.json", "data/prompt_response_map.json",
                "data/matrices/messages.csv", "data/matrices/messages.jsonl", "data/case_study_map.json",
                "data/case_study_nodes.csv", "data/case_study_edges.csv", "data/tensors/summary.json",
                "cell_index.json", "logs/verification.log", "schemas/case_study_map.schema.json",
                "schemas/cell_root.schema.json", "schemas/tensor_summary.schema.json",
                "manifests/file_hashes.sha256", "manifests/seal_receipt.json", "manifests/cell_root.json", "README.md",
            ]
            for rel in required:
                with self.subTest(path=rel): self.assertTrue((cell / rel).is_file())
            readme = (cell / "README.md").read_text(encoding="utf-8")
            self.assertIn("What this is NOT", readme)
            self.assertIn("Tensor summary is mechanical", readme)
            self.assertIn("result=PASS", (cell / "logs" / "verification.log").read_text(encoding="utf-8"))

            self._validate("prompt_log.schema.json", json.loads((cell / "data/prompt_log.json").read_text(encoding="utf-8")))
            self._validate("prompt_response_map.schema.json", json.loads((cell / "data/prompt_response_map.json").read_text(encoding="utf-8")))
            self._validate("case_study_map.schema.json", json.loads((cell / "data/case_study_map.json").read_text(encoding="utf-8")))
            self._validate("tensor_summary.schema.json", json.loads((cell / "data/tensors/summary.json").read_text(encoding="utf-8")))
            self._validate("cell_index.schema.json", json.loads((cell / "cell_index.json").read_text(encoding="utf-8")))
            self._validate("seal_receipt.schema.json", json.loads((cell / "manifests/seal_receipt.json").read_text(encoding="utf-8")))
            self._validate("cell_root.schema.json", json.loads((cell / "manifests/cell_root.json").read_text(encoding="utf-8")))
            ok, errors = amcs.verify_cell_dir(cell)
            self.assertTrue(ok, errors)

    def test_sealed_cell_is_no_clobber(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); args = self._seal_args(root, self._chat(root))
            first = Path(amcs.seal(args)); before = first.read_bytes()
            with self.assertRaises(amcs.AMCSSecurityError): amcs.seal(args)
            self.assertEqual(first.read_bytes(), before)

    def test_unanswered_prompt_fails_closed_unless_explicitly_marked(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            chat = self._chat(root, [{"role": "user", "content": "do this"}])
            with self.assertRaises(amcs.AMCSValidationError): amcs.seal(self._seal_args(root, chat))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            chat = self._chat(root, [{"role": "user", "content": "FYI only", "no_response_required": True}])
            archive = Path(amcs.seal(self._seal_args(root, chat)))
            self.assertTrue(amcs.verify_archive(archive)[0])

    def test_orphan_assistant_response_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            chat = self._chat(root, [
                {"role": "assistant", "content": "orphan"},
                {"role": "user", "content": "FYI", "no_response_required": True},
            ])
            with self.assertRaises(amcs.AMCSValidationError): amcs.seal(self._seal_args(root, chat))

    def test_attachment_provenance_is_bound_into_matrix(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachments = root / "attachments"; attachments.mkdir()
            (attachments / "evidence.txt").write_text("evidence", encoding="utf-8")
            chat = self._chat(root, [
                {"role": "user", "content": "review", "attachments": ["evidence.txt"]},
                {"role": "assistant", "content": "reviewed"},
            ])
            archive = Path(amcs.seal(self._seal_args(root, chat, attachments_root=str(attachments))))
            cell = self._extract(archive, root)
            rows = [json.loads(line) for line in (cell / "data/matrices/messages.jsonl").read_text(encoding="utf-8").splitlines()]
            self.assertEqual(rows[0]["source_artifact_refs"], ["evidence/evidence.txt"])
            self.assertTrue((cell / rows[0]["source_artifact_refs"][0]).is_file())
            self.assertEqual(rows[1]["source_artifact_refs"], [])

    def test_graph_referential_integrity_detects_unknown_endpoint(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = Path(amcs.seal(self._seal_args(root, self._chat(root))))
            cell = self._extract(archive, root)
            graph_path = cell / "data/case_study_map.json"
            graph = json.loads(graph_path.read_text(encoding="utf-8"))
            graph["edges"][0]["to_node_id"] = "MISSING"
            graph_path.write_text(json.dumps(graph), encoding="utf-8")
            errors = amcs._verify_graph_references(cell)
            self.assertTrue(any("unknown node" in error for error in errors))

    def test_authenticated_root_requires_matching_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); key_hex = "11" * 32
            archive = Path(amcs.seal(self._seal_args(root, self._chat(root), seal_key_hex=key_hex)))
            self.assertFalse(amcs.verify_archive(archive)[0])
            self.assertTrue(amcs.verify_archive(archive, seal_key=bytes.fromhex(key_hex))[0])
            cell = self._extract(archive, root)
            receipt = json.loads((cell / "manifests/seal_receipt.json").read_text(encoding="utf-8"))
            receipt["scope"] = "tampered"
            (cell / "manifests/seal_receipt.json").write_text(json.dumps(receipt), encoding="utf-8")
            ok, errors = amcs.verify_cell_dir(cell, seal_key=bytes.fromhex(key_hex))
            self.assertFalse(ok)
            self.assertTrue(any("receipt binding" in error for error in errors))

    def test_delta_requires_complete_lineage_and_stable_case_study_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); chat = self._chat(root)
            with self.assertRaises(amcs.AMCSValidationError):
                amcs.seal(self._seal_args(root, chat, parent_cell_hash="a" * 64))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); chat = self._chat(root)
            with self.assertRaises(amcs.AMCSValidationError):
                amcs.seal(self._seal_args(root, chat, parent_cell_hash="a" * 64, delta_type="additive"))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); chat = self._chat(root)
            archive = Path(amcs.seal(self._seal_args(
                root, chat, parent_cell_hash="a" * 64, delta_type="additive", case_study_id="CASE_1"
            )))
            cell = self._extract(archive, root)
            receipt = json.loads((cell / "manifests/seal_receipt.json").read_text(encoding="utf-8"))
            index = json.loads((cell / "cell_index.json").read_text(encoding="utf-8"))
            self.assertEqual(receipt["parent_cell_hash"], "a" * 64)
            self.assertEqual(receipt["delta_type"], "additive")
            self.assertEqual(receipt["case_study_id"], "CASE_1")
            self.assertEqual(index["case_study_id"], "CASE_1")

    def test_supercell_manifest_matches_schema_and_is_no_clobber(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); archive = Path(amcs.seal(self._seal_args(root, self._chat(root))))
            args = argparse.Namespace(
                cells=[str(archive)], out_dir=str(root / "super"), supercell_name="SUPER_1", scope="test",
                mode="research", reason="test", notes="", max_archive_members=10000,
                max_expanded_bytes=512 * 1024 * 1024,
            )
            supercell = Path(amcs.assemble_supercell(args))
            extracted = root / "super_extract"; amcs.safe_extract_tar(supercell, extracted)
            superroot = amcs._single_root(extracted)
            manifest = json.loads((superroot / "supercell_manifest.json").read_text(encoding="utf-8"))
            self._validate("supercell_manifest.schema.json", manifest)
            with self.assertRaises(amcs.AMCSSecurityError): amcs.assemble_supercell(args)


if __name__ == "__main__":
    unittest.main()
