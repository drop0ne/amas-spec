#!/usr/bin/env python3
"""Canonical JSON v1 for AMAS/AAB security objects.

The encoding deliberately narrows JSON to a deterministic interoperable subset:
objects with string keys, arrays, Unicode scalar strings, safe-range integers,
booleans, and null. Floating point values and language-specific extensions are
forbidden.
"""
from __future__ import annotations

import hashlib
from typing import Any


class CanonicalJSONError(ValueError):
    pass


MAX_SAFE_INTEGER = (1 << 53) - 1
MIN_SAFE_INTEGER = -MAX_SAFE_INTEGER

_ESCAPE = {
    0x08: "\\b",
    0x09: "\\t",
    0x0A: "\\n",
    0x0C: "\\f",
    0x0D: "\\r",
}


def _validate_string(value: str, path: str) -> None:
    if any(0xD800 <= ord(ch) <= 0xDFFF for ch in value):
        raise CanonicalJSONError(f"Unicode surrogate forbidden at {path}")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise CanonicalJSONError(f"invalid Unicode string at {path}") from exc


def _quote(value: str, path: str) -> str:
    _validate_string(value, path)
    out = ['"']
    for ch in value:
        code = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif code <= 0x1F:
            out.append(_ESCAPE.get(code, f"\\u{code:04x}"))
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _key_order(value: str) -> bytes:
    _validate_string(value, "$.<key>")
    return value.encode("utf-16-be", errors="strict")


def validate(value: Any, path: str = "$") -> None:
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        if value < MIN_SAFE_INTEGER or value > MAX_SAFE_INTEGER:
            raise CanonicalJSONError(f"integer outside interoperable safe range at {path}")
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


def _serialize(value: Any, path: str) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int) and not isinstance(value, bool):
        if value < MIN_SAFE_INTEGER or value > MAX_SAFE_INTEGER:
            raise CanonicalJSONError(f"integer outside interoperable safe range at {path}")
        return str(value)
    if isinstance(value, float):
        raise CanonicalJSONError(f"floating-point value forbidden at {path}")
    if isinstance(value, str):
        return _quote(value, path)
    if isinstance(value, list):
        return "[" + ",".join(_serialize(item, f"{path}[{index}]") for index, item in enumerate(value)) + "]"
    if isinstance(value, dict):
        keys = list(value.keys())
        if any(not isinstance(key, str) for key in keys):
            raise CanonicalJSONError(f"non-string object key at {path}")
        keys.sort(key=_key_order)
        return "{" + ",".join(_quote(key, f"{path}.<key>") + ":" + _serialize(value[key], f"{path}.{key}") for key in keys) + "}"
    raise CanonicalJSONError(f"non-JSON type at {path}:{type(value).__name__}")


def dumps(value: Any) -> str:
    try:
        return _serialize(value, "$")
    except RecursionError as exc:
        raise CanonicalJSONError("canonical JSON nesting is too deep") from exc


def bytes_(value: Any) -> bytes:
    try:
        return dumps(value).encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise CanonicalJSONError("canonical JSON UTF-8 encoding failed") from exc


def sha256(value: Any) -> str:
    return hashlib.sha256(bytes_(value)).hexdigest()
