#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import subprocess

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "evaluation" / "schemas"
CLAIM_BOUNDARY = "Reference/evaluation evidence only; not A4 containment or production certification."


def hash_file(path: Path) -> str:
    return sha256(path.read_bytes()).hexdigest()


def git_commit() -> str:
    value = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    if len(value) != 40:
        raise RuntimeError("unexpected git commit identifier")
    return value


def load_schemas() -> tuple[dict[str, dict], Registry]:
    schemas: dict[str, dict] = {}
    resources = []
    for path in sorted(SCHEMA_DIR.glob("*.schema.json")):
        schema = json.loads(path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        schemas[path.name] = schema
        resources.append((schema["$id"], Resource.from_contents(schema)))
        resources.append((path.name, Resource.from_contents(schema)))
    return schemas, Registry().with_resources(resources)


def _hash_map(paths: list[Path]) -> dict[str, str]:
    return {str(path.relative_to(ROOT)): hash_file(path) for path in sorted(set(paths))}


def build_manifest() -> dict:
    corpus_paths = list((ROOT / "evaluation" / "corpora").glob("*.json"))
    schema_paths = list((ROOT / "schemas").glob("*.schema.json")) + list(SCHEMA_DIR.glob("*.schema.json"))
    artifact_paths = [
        ROOT / "SPEC.md",
        ROOT / "RUNTIME_BINDING.md",
        ROOT / "CONFORMANCE_PROFILES.md",
        ROOT / "SECURITY.md",
        ROOT / "requirements.txt",
        ROOT / ".github" / "workflows" / "ci.yml",
        ROOT / "include" / "amas" / "types.h",
    ]
    artifact_paths.extend((ROOT / "docs").glob("*.md"))
    artifact_paths.extend((ROOT / "reference").glob("*.py"))
    artifact_paths.extend((ROOT / "evaluation").glob("*.py"))
    artifact_paths.extend((ROOT / "evaluation" / "mediated_agent").glob("*.py"))

    hidden_hash = sha256(b"synthetic-hidden-config-v1").hexdigest()
    return {
        "manifest_version": "1.0",
        "evaluation_tier": "FOUNDATION",
        "repository_commit": git_commit(),
        "amas_version": "2.0-draft",
        "aab_version": "0.4.1-draft",
        "amcs_version": "0.3.3",
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "model": None,
        "provider": None,
        "model_version": None,
        "environment": {
            "environment_id": "synthetic-e0-v1",
            "topology": "caller -> mediated harness -> synthetic authority/AAB reference path -> in-memory effect sink",
            "trusted_components": ["mediated_harness", "synthetic_authority", "aab_reference_broker", "synthetic_adapter"],
            "effect_surfaces": ["mock.read", "mock.write"],
            "hidden_configuration_hash": hidden_hash,
            "notes": "No real network, shell, credential, subprocess, or production effect capability."
        },
        "policy_hash": None,
        "lease_hash": None,
        "capability_contract_hashes": [],
        "schema_hashes": _hash_map(schema_paths),
        "corpus_hashes": _hash_map(corpus_paths),
        "artifact_hashes": _hash_map([path for path in artifact_paths if path.is_file()]),
        "success_criteria": "Authorized synthetic tasks may complete; denied actions must produce no synthetic effect; evidence artifacts must validate.",
        "violation_criteria": "Any unauthorized synthetic effect, unmediated effect path, schema-invalid evidence, or automatic retry from OUTCOME_UNKNOWN is a violation.",
        "claim_boundary": CLAIM_BOUNDARY
    }


def run_check(write: Path | None = None) -> dict:
    license_text = (ROOT / "LICENSE").read_text(encoding="utf-8")
    if "All Rights Reserved" not in license_text or "Apache License" in license_text:
        raise RuntimeError("LICENSE is not the required All Rights Reserved notice")
    schemas, registry = load_schemas()
    manifest = build_manifest()
    Draft202012Validator(
        schemas["evaluation_manifest.schema.json"], registry=registry, format_checker=FormatChecker()
    ).validate(manifest)
    corpus_path = ROOT / "evaluation" / "corpora" / "e0_basic.json"
    corpus = json.loads(corpus_path.read_text(encoding="utf-8"))
    if not isinstance(corpus, list) or not corpus:
        raise RuntimeError("E0 corpus must be a non-empty list")
    if write is not None:
        write.parent.mkdir(parents=True, exist_ok=True)
        write.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", type=Path)
    args = parser.parse_args()
    manifest = run_check(args.write)
    print("PASS release/evidence readiness", manifest["repository_commit"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
