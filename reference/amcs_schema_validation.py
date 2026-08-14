#!/usr/bin/env python3
"""Schema validation helpers for AMCS generated JSON surfaces."""
from __future__ import annotations

import datetime
import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker, ValidationError

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "schemas"
ARTIFACT_SCHEMAS = {
    "data/prompt_log.json": "prompt_log.schema.json",
    "data/prompt_response_map.json": "prompt_response_map.schema.json",
    "data/case_study_map.json": "case_study_map.schema.json",
    "data/tensors/summary.json": "tensor_summary.schema.json",
    "cell_index.json": "cell_index.schema.json",
    "manifests/seal_receipt.json": "seal_receipt.schema.json",
    "manifests/cell_root.json": "cell_root.schema.json",
}
INPUT_FIELDS = {"role", "content", "timestamp", "attachments", "no_response_required"}


class AMCSSchemaError(ValueError):
    pass


def load_json(path: str | Path) -> Any:
    return json.loads(
        Path(path).read_text(encoding="utf-8"),
        parse_constant=lambda value: (_ for _ in ()).throw(ValueError(f"non-finite JSON constant:{value}")),
    )


def validate_json_input(path: str | Path) -> None:
    source = Path(path)
    if source.suffix.lower() != ".json":
        return
    data = load_json(source)
    if not isinstance(data, list) or not data:
        raise AMCSSchemaError("JSON input must be a non-empty list of message objects")
    for index, item in enumerate(data):
        if not isinstance(item, dict):
            raise AMCSSchemaError(f"message {index} must be an object")
        extra = sorted(set(item) - INPUT_FIELDS)
        if extra:
            raise AMCSSchemaError(f"message {index} contains unknown field:{extra[0]}")
        if item.get("role") not in {"user", "assistant"} or not isinstance(item.get("content"), str):
            raise AMCSSchemaError(f"message {index} has invalid role/content")
        timestamp = item.get("timestamp")
        if timestamp is not None:
            if not isinstance(timestamp, str) or not timestamp:
                raise AMCSSchemaError(f"message {index} timestamp must be date-time text or null")
            candidate = timestamp[:-1] + "+00:00" if timestamp.endswith("Z") else timestamp
            try:
                parsed = datetime.datetime.fromisoformat(candidate)
            except ValueError as exc:
                raise AMCSSchemaError(f"message {index} timestamp is invalid") from exc
            if parsed.tzinfo is None:
                raise AMCSSchemaError(f"message {index} timestamp must include timezone")
        attachments = item.get("attachments", [])
        if not isinstance(attachments, list) or any(not isinstance(value, str) or not value for value in attachments):
            raise AMCSSchemaError(f"message {index} attachments must contain non-empty strings")
        no_response = item.get("no_response_required", False)
        if not isinstance(no_response, bool) or (item["role"] == "assistant" and no_response):
            raise AMCSSchemaError(f"message {index} has invalid no_response_required")


def validator(schema_name: str) -> Draft202012Validator:
    schema = load_json(SCHEMAS / schema_name)
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=FormatChecker())


def validate_cell_directory(cell: str | Path) -> list[str]:
    root = Path(cell)
    errors: list[str] = []
    for relative, schema_name in ARTIFACT_SCHEMAS.items():
        path = root / relative
        if not path.is_file():
            errors.append(f"missing schema-validated artifact:{relative}")
            continue
        try:
            validator(schema_name).validate(load_json(path))
        except (OSError, ValueError, json.JSONDecodeError, ValidationError) as exc:
            errors.append(f"schema validation failed:{relative}:{type(exc).__name__}:{exc}")
    return errors


def validate_supercell_directory(root: str | Path) -> list[str]:
    path = Path(root) / "supercell_manifest.json"
    if not path.is_file():
        return ["missing supercell_manifest.json"]
    try:
        validator("supercell_manifest.schema.json").validate(load_json(path))
        return []
    except (OSError, ValueError, json.JSONDecodeError, ValidationError) as exc:
        return [f"supercell schema validation failed:{type(exc).__name__}:{exc}"]
