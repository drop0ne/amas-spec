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
    def _chat(self, root: Path, messages=None, name="chat.json") -> Path:
        path = root / name
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
            "parent_cell": None, "parent_seal_key_hex": None, "delta_type": None,
            "case_study_id": None, "seal_key_hex": None,
            "max_archive_members": amcs.DEFAULT_MAX_ARCHIVE_MEMBERS,
            "max_expanded_bytes": amcs.DEFAULT_MAX_EXPANDED_BYTES,
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

            graph = json.loads((cell / "data/case_study_map.json").read_text(encoding="utf-8"))
            message_nodes = [node for node in graph["nodes"] if node["node_id"].startswith("NMSG")]
            self.assertTrue(message_nodes)
            self.assertTrue(all(node["node_type"] == "evidence_item" for node in message_nodes))

    def test_base_case_study_identity_depends_on_source_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = Path(amcs.seal(self._seal_args(root, self._chat(root, name="a.json"), cell_name="CELL_A")))
            second_chat = self._chat(root, [
                {"role": "user", "content": "different source"},
                {"role": "assistant", "content": "different response"},
            ], name="b.json")
            second = Path(amcs.seal(self._seal_args(root, second_chat, cell_name="CELL_B")))
            first_root = self._extract(first, root, "extract_a")
            second_root = self._extract(second, root, "extract_b")
            first_id = json.loads((first_root / "cell_index.json").read_text(encoding="utf-8"))["case_study_id"]
            second_id = json.loads((second_root / "cell_index.json").read_text(encoding="utf-8"))["case_study_id"]
            self.assertNotEqual(first_id, second_id)

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

    def test_authenticated_root_requires_matching_key_and_rejects_mode_downgrade(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); key_hex = "11" * 32; key = bytes.fromhex(key_hex)
            archive = Path(amcs.seal(self._seal_args(root, self._chat(root), seal_key_hex=key_hex)))
            self.assertFalse(amcs.verify_archive(archive)[0])
            self.assertTrue(amcs.verify_archive(archive, seal_key=key)[0])
            cell = self._extract(archive, root)
            receipt = json.loads((cell / "manifests/seal_receipt.json").read_text(encoding="utf-8"))
            receipt["scope"] = "tampered"
            (cell / "manifests/seal_receipt.json").write_text(json.dumps(receipt), encoding="utf-8")
            ok, errors = amcs.verify_cell_dir(cell, seal_key=key)
            self.assertFalse(ok)
            self.assertTrue(any("receipt binding" in error for error in errors))

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); key_hex = "22" * 32; key = bytes.fromhex(key_hex)
            archive = Path(amcs.seal(self._seal_args(root, self._chat(root), seal_key_hex=key_hex)))
            cell = self._extract(archive, root)
            root_path = cell / "manifests/cell_root.json"
            record = json.loads(root_path.read_text(encoding="utf-8"))
            record["authentication_alg"] = "NONE"
            record["root_mac"] = None
            payload = {k: record[k] for k in (
                "root_version", "cell_id", "case_study_id", "content_manifest_hash",
                "seal_receipt_hash", "cell_index_hash", "parent_cell_hash", "delta_type", "authentication_alg"
            )}
            record["root_hash"] = amcs.canonical_hash(payload)
            root_path.write_text(json.dumps(record), encoding="utf-8")
            ok, errors = amcs.verify_cell_dir(cell, seal_key=key)
            self.assertFalse(ok)
            self.assertTrue(any("not authenticated" in error for error in errors))

    def test_delta_lineage_is_derived_from_verified_parent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            parent = Path(amcs.seal(self._seal_args(root, self._chat(root, name="parent.json"), cell_name="PARENT")))
            parent_root = self._extract(parent, root, "parent_extract")
            parent_case_id = json.loads((parent_root / "cell_index.json").read_text(encoding="utf-8"))["case_study_id"]

            delta_chat = self._chat(root, [
                {"role": "user", "content": "new evidence"},
                {"role": "assistant", "content": "recorded"},
            ], name="delta.json")
            child = Path(amcs.seal(self._seal_args(
                root, delta_chat, cell_name="DELTA", parent_cell=str(parent), delta_type="additive"
            )))
            child_root = self._extract(child, root, "child_extract")
            receipt = json.loads((child_root / "manifests/seal_receipt.json").read_text(encoding="utf-8"))
            index = json.loads((child_root / "cell_index.json").read_text(encoding="utf-8"))
            self.assertEqual(receipt["parent_cell_hash"], amcs.sha256_file(parent))
            self.assertEqual(receipt["delta_type"], "additive")
            self.assertEqual(receipt["case_study_id"], parent_case_id)
            self.assertEqual(index["case_study_id"], parent_case_id)

            with self.assertRaises(amcs.AMCSValidationError):
                amcs.seal(self._seal_args(
                    root, delta_chat, cell_name="DELTA_BAD_ID", parent_cell=str(parent),
                    delta_type="additive", case_study_id="OTHER_CASE"
                ))

    def test_delta_requires_parent_and_rejects_unverified_parent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); chat = self._chat(root)
            with self.assertRaises(amcs.AMCSValidationError):
                amcs.seal(self._seal_args(root, chat, delta_type="additive"))
            bogus = root / "bogus.tar.gz"; bogus.write_bytes(b"not a tar")
            with self.assertRaises(amcs.AMCSValidationError):
                amcs.seal(self._seal_args(root, chat, cell_name="DELTA", parent_cell=str(bogus), delta_type="additive"))

    def test_supercell_manifest_matches_schema_and_is_no_clobber(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); archive = Path(amcs.seal(self._seal_args(root, self._chat(root))))
            args = argparse.Namespace(
                cells=[str(archive)], out_dir=str(root / "super"), supercell_name="SUPER_1", scope="test",
                mode="research", reason="test", notes="", seal_key_hex=None,
                max_archive_members=10000, max_expanded_bytes=512 * 1024 * 1024,
            )
            supercell = Path(amcs.assemble_supercell(args))
            extracted = root / "super_extract"; amcs.safe_extract_tar(supercell, extracted)
            superroot = amcs._single_root(extracted)
            manifest = json.loads((superroot / "supercell_manifest.json").read_text(encoding="utf-8"))
            self._validate("supercell_manifest.schema.json", manifest)
            with self.assertRaises(amcs.AMCSSecurityError): amcs.assemble_supercell(args)

    def test_supercell_can_verify_authenticated_children_with_explicit_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); key_hex = "33" * 32
            archive = Path(amcs.seal(self._seal_args(root, self._chat(root), seal_key_hex=key_hex)))
            args = argparse.Namespace(
                cells=[str(archive)], out_dir=str(root / "super"), supercell_name="SUPER_AUTH", scope="test",
                mode="research", reason="test", notes="", seal_key_hex=key_hex,
                max_archive_members=10000, max_expanded_bytes=512 * 1024 * 1024,
            )
            self.assertTrue(Path(amcs.assemble_supercell(args)).is_file())


if __name__ == "__main__":
    unittest.main()
