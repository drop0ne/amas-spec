import hashlib
from pathlib import Path
import tempfile
import unittest

from evaluation.mediated_agent.e1_planner import run_e1
from evaluation.mediated_agent.runner import run_e0
from evaluation.release_check import run_check


def file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class EvaluationManifestBindingTests(unittest.TestCase):
    def test_foundation_manifest_uses_v11_and_empty_evidence_binding(self):
        manifest = run_check()
        self.assertEqual(manifest["manifest_version"], "1.1")
        self.assertEqual(manifest["evaluation_tier"], "FOUNDATION")
        self.assertEqual(manifest["evidence_hashes"], {})
        self.assertEqual(manifest["trust_boundary"]["mode"], "none")
        self.assertFalse(manifest["trust_boundary"]["independent_failure_domain"])

    def test_e0_manifest_binds_exact_evidence_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            evidence = run_e0(out)
            manifest = evidence["manifest"]
            self.assertEqual(manifest["evaluation_tier"], "E0")
            self.assertEqual(set(manifest["evidence_hashes"]), {"trials.json", "results.json", "violations.json", "summary.json"})
            self.assertNotIn("evaluation_manifest.json", manifest["evidence_hashes"])
            for name, expected in manifest["evidence_hashes"].items():
                self.assertEqual(file_hash(out / name), expected)

            original = manifest["evidence_hashes"]["summary.json"]
            with (out / "summary.json").open("ab") as handle:
                handle.write(b" ")
            self.assertNotEqual(file_hash(out / "summary.json"), original)

    def test_e1_manifest_binds_authority_and_evidence_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            evidence = run_e1(out)
            manifest = evidence["manifest"]
            self.assertEqual(manifest["evaluation_tier"], "E1")
            self.assertIsNotNone(manifest["policy_hash"])
            self.assertIsNotNone(manifest["lease_hash"])
            self.assertEqual(len(manifest["capability_contract_hashes"]), 1)
            self.assertEqual(manifest["trust_boundary"]["mode"], "same_process_reference")
            self.assertFalse(manifest["trust_boundary"]["independent_failure_domain"])
            for name, expected in manifest["evidence_hashes"].items():
                self.assertEqual(file_hash(out / name), expected)


if __name__ == "__main__":
    unittest.main()
