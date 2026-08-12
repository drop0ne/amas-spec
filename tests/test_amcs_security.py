import argparse
import io
import json
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REFERENCE = Path(__file__).resolve().parents[1] / "reference"
sys.path.insert(0, str(REFERENCE))

import amcs


class AMCSPersistenceSecurityTests(unittest.TestCase):
    def _chat(self, root: Path, *, attachments=None) -> Path:
        path = root / "chat.json"
        path.write_text(
            json.dumps([
                {"role": "user", "content": "hello", "attachments": attachments or []},
                {"role": "assistant", "content": "world"},
            ]),
            encoding="utf-8",
        )
        return path

    def _seal_args(self, root: Path, chat: Path, **overrides):
        values = {
            "input": str(chat),
            "out_dir": str(root / "out"),
            "cell_name": "CELL_1",
            "scope": "entire_chat",
            "primary_narrative_source": "chat",
            "odt": None,
            "attachments_root": None,
            "genesis_prompt": None,
            "parse_session_header": True,
        }
        values.update(overrides)
        return argparse.Namespace(**values)

    def test_cell_identifier_rejects_path_traversal(self):
        with self.assertRaises(amcs.AMCSSecurityError):
            amcs._validate_identifier("../../outside", "cell-name")
        with self.assertRaises(amcs.AMCSSecurityError):
            amcs._validate_identifier("/tmp/outside", "cell-name")

    def test_round_trip_seal_and_verify(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = Path(amcs.seal(self._seal_args(root, self._chat(root))))
            self.assertTrue(archive.is_file())
            ok, errors = amcs.verify_archive(archive)
            self.assertTrue(ok, errors)

    def test_failed_preseal_verification_emits_no_archive(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            args = self._seal_args(root, self._chat(root))
            output = Path(args.out_dir) / "CELL_1.tar.gz"
            with mock.patch.object(amcs, "verify_cell_dir", return_value=(False, ["forced failure"])):
                with self.assertRaises(amcs.AMCSValidationError):
                    amcs.seal(args)
            self.assertFalse(output.exists())

    def test_tar_traversal_member_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "bad.tar.gz"
            with tarfile.open(archive, "w:gz") as tar:
                data = b"escape"
                info = tarfile.TarInfo("../escape.txt")
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
            with self.assertRaises(amcs.AMCSSecurityError):
                amcs.safe_extract_tar(archive, root / "extract")
            self.assertFalse((root / "escape.txt").exists())

    def test_tar_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "link.tar.gz"
            with tarfile.open(archive, "w:gz") as tar:
                info = tarfile.TarInfo("CELL/link")
                info.type = tarfile.SYMTYPE
                info.linkname = "/etc/passwd"
                tar.addfile(info)
            with self.assertRaises(amcs.AMCSSecurityError):
                amcs.safe_extract_tar(archive, root / "extract")

    def test_archive_member_limit_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "many.tar.gz"
            with tarfile.open(archive, "w:gz") as tar:
                for index in range(3):
                    data = str(index).encode()
                    info = tarfile.TarInfo(f"CELL/{index}.txt")
                    info.size = len(data)
                    tar.addfile(info, io.BytesIO(data))
            with self.assertRaises(amcs.AMCSSecurityError):
                amcs.safe_extract_tar(archive, root / "extract", max_members=2)

    def test_attachment_traversal_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachments = root / "attachments"
            attachments.mkdir()
            outside = root / "secret.txt"
            outside.write_text("secret", encoding="utf-8")
            chat = self._chat(root, attachments=["../secret.txt"])
            args = self._seal_args(root, chat, attachments_root=str(attachments))
            with self.assertRaises(amcs.AMCSSecurityError):
                amcs.seal(args)

    def test_absolute_message_attachment_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            attachments = root / "attachments"
            attachments.mkdir()
            target = attachments / "evidence.txt"
            target.write_text("evidence", encoding="utf-8")
            chat = self._chat(root, attachments=[str(target.resolve())])
            args = self._seal_args(root, chat, attachments_root=str(attachments))
            with self.assertRaises(amcs.AMCSSecurityError):
                amcs.seal(args)

    def test_supercell_rejects_unverified_child(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bad = root / "bad.tar.gz"
            with tarfile.open(bad, "w:gz") as tar:
                data = b"not a cell"
                info = tarfile.TarInfo("BAD/file.txt")
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
            args = argparse.Namespace(
                cells=[str(bad)],
                out_dir=str(root / "out"),
                supercell_name="SUPER_1",
                scope="test",
                mode="research",
                reason=None,
                notes=None,
                max_archive_members=100,
                max_expanded_bytes=1024 * 1024,
            )
            with self.assertRaises(amcs.AMCSValidationError):
                amcs.assemble_supercell(args)


if __name__ == "__main__":
    unittest.main()
