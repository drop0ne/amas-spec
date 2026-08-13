#!/usr/bin/env python3
"""Supported schema-validating entrypoint for the AMCS 0.3.3 reference engine."""
from __future__ import annotations

import argparse
import tarfile
import tempfile
from pathlib import Path

import amcs
from amcs_schema_validation import AMCSSchemaError, validate_cell_directory, validate_json_input, validate_supercell_directory


def validate_archive(path, *, seal_key=None, max_members=amcs.DEFAULT_MAX_ARCHIVE_MEMBERS, max_expanded_bytes=amcs.DEFAULT_MAX_EXPANDED_BYTES):
    ok, errors = amcs.verify_archive(path, seal_key=seal_key, max_members=max_members, max_expanded_bytes=max_expanded_bytes)
    if not ok:
        return False, errors
    try:
        with tempfile.TemporaryDirectory(prefix="amcs_conformance_") as tmp:
            root = Path(tmp)
            amcs.safe_extract_tar(path, root, max_members=max_members, max_expanded_bytes=max_expanded_bytes)
            errors = validate_cell_directory(amcs._single_root(root))
            return not errors, errors
    except (amcs.AMCSError, OSError, ValueError, tarfile.TarError) as exc:
        return False, [f"conformance validation failed:{type(exc).__name__}:{exc}"]


def seal(args):
    validate_json_input(args.input)
    archive = Path(amcs.seal(args))
    key = amcs._parse_seal_key(getattr(args, "seal_key_hex", None))
    ok, errors = validate_archive(archive, seal_key=key, max_members=args.max_archive_members, max_expanded_bytes=args.max_expanded_bytes)
    if not ok:
        archive.unlink(missing_ok=True)
        raise AMCSSchemaError("sealed output failed schema validation: " + "; ".join(errors))
    return str(archive)


def verify(args):
    key = amcs._parse_seal_key(getattr(args, "seal_key_hex", None))
    ok, errors = validate_archive(args.cell, seal_key=key, max_members=args.max_archive_members, max_expanded_bytes=args.max_expanded_bytes)
    if ok:
        print("PASS")
        return 0
    print("FAIL")
    for error in errors:
        print("-", error)
    return 1


def assemble(args):
    key = amcs._parse_seal_key(getattr(args, "seal_key_hex", None))
    for child in args.cells:
        ok, errors = validate_archive(child, seal_key=key, max_members=args.max_archive_members, max_expanded_bytes=args.max_expanded_bytes)
        if not ok:
            raise AMCSSchemaError(f"child cell failed conformance:{child}: {'; '.join(errors)}")
    archive = Path(amcs.assemble_supercell(args))
    try:
        with tempfile.TemporaryDirectory(prefix="amcs_supercell_conformance_") as tmp:
            root = Path(tmp)
            amcs.safe_extract_tar(archive, root, max_members=args.max_archive_members, max_expanded_bytes=args.max_expanded_bytes)
            errors = validate_supercell_directory(amcs._single_root(root))
    except (amcs.AMCSError, OSError, ValueError, tarfile.TarError) as exc:
        errors = [f"supercell validation failed:{type(exc).__name__}:{exc}"]
    if errors:
        archive.unlink(missing_ok=True)
        raise AMCSSchemaError("supercell failed schema validation: " + "; ".join(errors))
    return str(archive)


def parser():
    p = argparse.ArgumentParser(description="AMCS schema-validating conformance runtime")
    sub = p.add_subparsers(dest="cmd", required=True)
    ps = sub.add_parser("seal")
    ps.add_argument("--input", required=True); ps.add_argument("--out-dir", required=True); ps.add_argument("--cell-name", required=True)
    ps.add_argument("--scope", default="entire_chat"); ps.add_argument("--primary-narrative-source", default=None, choices=["odt", "chat", "both"])
    ps.add_argument("--odt", default=None); ps.add_argument("--attachments-root", default=None); ps.add_argument("--genesis-prompt", default=None); ps.add_argument("--seal-key-hex", default=None)
    ps.add_argument("--parent-cell", default=None); ps.add_argument("--parent-seal-key-hex", default=None); ps.add_argument("--delta-type", choices=["additive", "corrective", "contextual"], default=None); ps.add_argument("--case-study-id", default=None)
    ps.add_argument("--max-archive-members", type=int, default=amcs.DEFAULT_MAX_ARCHIVE_MEMBERS); ps.add_argument("--max-expanded-bytes", type=int, default=amcs.DEFAULT_MAX_EXPANDED_BYTES)
    g = ps.add_mutually_exclusive_group(); g.add_argument("--parse-session-header", dest="parse_session_header", action="store_true", default=True); g.add_argument("--no-parse-session-header", dest="parse_session_header", action="store_false")
    pv = sub.add_parser("verify"); pv.add_argument("--cell", required=True); pv.add_argument("--seal-key-hex", default=None); pv.add_argument("--max-archive-members", type=int, default=amcs.DEFAULT_MAX_ARCHIVE_MEMBERS); pv.add_argument("--max-expanded-bytes", type=int, default=amcs.DEFAULT_MAX_EXPANDED_BYTES)
    pa = sub.add_parser("assemble-supercell"); pa.add_argument("--cells", nargs="+", required=True); pa.add_argument("--out-dir", required=True); pa.add_argument("--supercell-name", required=True); pa.add_argument("--scope", required=True); pa.add_argument("--mode", default="research", choices=["analysis", "research", "consolidation", "planning"]); pa.add_argument("--reason", default=None); pa.add_argument("--notes", default=None); pa.add_argument("--seal-key-hex", default=None); pa.add_argument("--max-archive-members", type=int, default=amcs.DEFAULT_MAX_ARCHIVE_MEMBERS); pa.add_argument("--max-expanded-bytes", type=int, default=amcs.DEFAULT_MAX_EXPANDED_BYTES)
    return p


def main():
    args = parser().parse_args()
    try:
        if args.cmd == "seal":
            print(seal(args)); return 0
        if args.cmd == "verify":
            return verify(args)
        if args.cmd == "assemble-supercell":
            print(assemble(args)); return 0
        return 2
    except (amcs.AMCSError, AMCSSchemaError, OSError, ValueError, tarfile.TarError) as exc:
        print(f"ERROR: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
