#!/usr/bin/env python3
"""Strict canonical JSON v1 for AMAS/AAB security objects.

This reference intentionally narrows JSON numbers to integers. Floating-point
serialization differs across language/runtime ecosystems and is unnecessary for
current authority, lease, receipt, budget, and capability-contract structures.
Tool APIs needing fractional values should bind an agreed textual decimal or an
adapter-specific normalized representation before entering this security hash.

Canonical JSON v1:
- JSON objects with string keys only
- arrays preserve order
- strings are valid UTF-8 Unicode scalar sequences (no surrogate code points)
- integers only for numeric values; booleans are distinct from integers
- true/false/null supported
- object keys sorted by Unicode code-point ordering
- UTF-8 output, no insignificant whitespace, no ASCII-only escaping
"""
from __future__ import annotations

import hashlib
import json
from typing import Any


class CanonicalJSONError(ValueError):
    pass


def _validate_string(value: str, path: str) -> None:
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise CanonicalJSONError(f"invalid Unicode string at {path}") from exc
    if any(0xD800 <= ord(ch) <= 0xDFFF for ch in value):
        raise CanonicalJSONError(f"Unicode surrogate forbidden at {path}")


def validate(value: Any, path: str = "$") -> None:
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        return
    if isinstance(value, float):
        raise CanonicalJSONError(f"floating-point value forbidden at {path}")
    if isinstance(value, str):
        _validate_string(value, path)
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            validate(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalJSONError(f"non-string object key at {path}")
            _validate_string(key, f"{path}.<key>")
            validate(item, f"{path}.{key}")
        return
    raise CanonicalJSONError(f"non-JSON type at {path}:{type(value).__name__}")


def dumps(value: Any) -> str:
    validate(value)
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError, RecursionError) as exc:
        raise CanonicalJSONError("canonical JSON serialization failed") from exc


def bytes_(value: Any) -> bytes:
    try:
        return dumps(value).encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise CanonicalJSONError("canonical JSON UTF-8 encoding failed") from exc


def sha256(value: Any) -> str:
    return hashlib.sha256(bytes_(value)).hexdigest()
