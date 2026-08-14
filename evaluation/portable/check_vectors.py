#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
REFERENCE = ROOT / "reference"
if str(REFERENCE) not in sys.path:
    sys.path.insert(0, str(REFERENCE))

import canonical_json  # type: ignore

VECTORS = ROOT / "evaluation" / "corpora" / "canonical_json_vectors.json"


def parse_emitter(path: Path) -> dict[str, str]:
    completed = subprocess.run([str(path)], check=True, capture_output=True, text=True, encoding="utf-8")
    found: dict[str, str] = {}
    for line in completed.stdout.splitlines():
        name, sep, canonical = line.partition("\t")
        if not sep or not name or name in found:
            raise RuntimeError(f"invalid emitter output line: {line!r}")
        found[name] = canonical
    return found


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--c", type=Path, required=True)
    parser.add_argument("--cpp", type=Path, required=True)
    args = parser.parse_args()

    vectors = json.loads(VECTORS.read_text(encoding="utf-8"))
    expected = {item["name"]: item for item in vectors}
    c_values = parse_emitter(args.c)
    cpp_values = parse_emitter(args.cpp)
    if set(c_values) != set(expected) or set(cpp_values) != set(expected):
        raise RuntimeError("portable emitters did not produce the complete golden-vector set")

    for name, vector in expected.items():
        python_value = canonical_json.dumps(vector["value"])
        values = {"python": python_value, "c": c_values[name], "cpp": cpp_values[name]}
        for language, value in values.items():
            if value != vector["canonical"]:
                raise RuntimeError(f"{name}:{language}: canonical bytes differ")
            digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
            if digest != vector["sha256"]:
                raise RuntimeError(f"{name}:{language}: SHA-256 differs")
        print("PASS", name, vector["sha256"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
