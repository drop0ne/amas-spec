#!/usr/bin/env python3
"""AMCS reference runtime — v0.3.3.

Implements the AMCS v1.2.1 INTERNAL profile with security/conformance hardening:
- complete chat crawl with explicit prompt/response omission accounting
- FIRST-ORDER matrix rows with prompt/response/message/evidence provenance
- case files, case-study graph JSON+CSV, and a mechanical tensor summary
- direct source provenance on tensor and cell-index surfaces
- cell index, copied schemas, verification log, manifests, seal receipt, cell root
- path-safe evidence handling and bounded traversal-safe archive extraction
- immutable no-clobber cell/supercell creation
- fail-closed pre-seal and archive verification
- optional HMAC-authenticated cell root with explicit verification-mode expectation
- redundant root metadata cross-bound to the sealed receipt and index
- verified delta parent lineage and inherited case-study identity
- verified child cells before supercell assembly

The CLI `seal` subcommand is itself an explicit operator hard trigger to seal; a
chat-local trigger phrase is therefore not required for this non-conversational
reference runtime.
"""
from __future__ import annotations

import argparse
import csv
import datetime
import hashlib
import hmac
import json
import os
import re
import shutil
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterable, List, Optional, Tuple

__version__ = "0.3.3"

AMCS_INIT_SEED_DEFAULT = (
    "Promote to a case study, so I want you to do is to quantify the data into an indexable "
    "structure consisting of multiple case files that collectively create a matrix (basic) tensor "
    "(multidimensional). Scope: entire chat;"
)
IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
SESSION_HEADER_RE = re.compile(r"^\[AMCS_SESSION_HEADER\s+v(?P<ver>[0-9.]+)\]\s*$", re.IGNORECASE)
DEFAULT_MAX_ARCHIVE_MEMBERS = 10_000
DEFAULT_MAX_EXPANDED_BYTES = 512 * 1024 * 1024

AMCS_SCHEMA_NAMES = (
    "case_study_map.schema.json",
    "cell_index.schema.json",
    "prompt_log.schema.json",
    "prompt_response_map.schema.json",
    "seal_receipt.schema.json",
    "cell_root.schema.json",
    "supercell_manifest.schema.json",
    "tensor_summary.schema.json",
)

HEADER_KEY_ALIASES = {
    "domain": "domain", "primary_question": "primary_question", "primaryquestion": "primary_question",
    "primary": "primary_question", "scope": "scope", "assumptions": "assumptions",
    "constraints": "constraints", "desired_output": "desired_output", "desiredoutput": "desired_output",
    "stop_condition": "stop_condition", "stopcondition": "stop_condition", "follow_ups": "follow_ups",
    "followups": "follow_ups", "sensitivity": "sensitivity", "exclusions": "exclusions",
}
HEADER_FIELD_ORDER = [
    "domain", "primary_question", "scope", "assumptions", "constraints", "desired_output",
    "stop_condition", "follow_ups", "sensitivity", "exclusions",
]


class AMCSError(RuntimeError):
    pass


class AMCSSecurityError(AMCSError):
    pass


class AMCSValidationError(AMCSError):
    pass


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")


def _norm_text(value: str) -> str:
    value = value.replace("\r\n", "\n").replace("\r", "\n")
    return "\n".join(line.rstrip() for line in value.split("\n"))


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def canonical_hash(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def sha256_text(value: str) -> str:
    return hashlib.sha256(_norm_text(value).encode("utf-8")).hexdigest()


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_identifier(value: str, field: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER_RE.fullmatch(value):
        raise AMCSSecurityError(f"{field} must be a 1-64 character identifier using letters, digits, ._- only")
    return value


def _resolved_child(root: str | Path, candidate: str | Path) -> Path:
    root_path = Path(root).resolve()
    candidate_path = Path(candidate).resolve()
    try:
        candidate_path.relative_to(root_path)
    except ValueError as exc:
        raise AMCSSecurityError(f"path escapes allowed root: {candidate_path}") from exc
    return candidate_path


def _safe_output_path(out_dir: str | Path, filename: str) -> Path:
    root = Path(out_dir).resolve()
    root.mkdir(parents=True, exist_ok=True)
    return _resolved_child(root, root / filename)


def _norm_key(key: str) -> str:
    key = re.sub(r"[\s\-/]+", "_", key.strip().lower())
    return re.sub(r"[^a-z0-9_]+", "", key)


def _split_list(value: str) -> List[str]:
    value = value.strip()
    if not value:
        return []
    parts = [part.strip() for part in value.split(";") if part.strip()]
    if len(parts) <= 1 and "," in value:
        parts = [part.strip() for part in value.split(",") if part.strip()]
    return parts


def _write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False, allow_nan=False) + "\n", encoding="utf-8")


def load_chat(path: str | Path) -> List[Dict[str, Any]]:
    source = Path(path)
    if source.suffix.lower() == ".json":
        data = json.loads(
            source.read_text(encoding="utf-8"),
            parse_constant=lambda value: (_ for _ in ()).throw(ValueError(f"non-finite JSON constant:{value}")),
        )
        if not isinstance(data, list) or not data:
            raise ValueError("JSON input must be a non-empty list of message objects")
        messages: List[Dict[str, Any]] = []
        for index, item in enumerate(data):
            if not isinstance(item, dict):
                raise ValueError(f"Message {index} is not an object")
            role, content = item.get("role"), item.get("content")
            attachments = item.get("attachments") or []
            if role not in ("user", "assistant"):
                raise ValueError(f"Message {index} role must be user or assistant")
            if not isinstance(content, str):
                raise ValueError(f"Message {index} content must be a string")
            if not isinstance(attachments, list) or any(not isinstance(a, str) or not a for a in attachments):
                raise ValueError(f"Message {index} attachments must be an array of non-empty strings")
            no_response = item.get("no_response_required", False)
            if not isinstance(no_response, bool):
                raise ValueError(f"Message {index} no_response_required must be boolean")
            if role == "assistant" and no_response:
                raise ValueError("no_response_required is valid only for user messages")
            messages.append({
                "role": role,
                "content": content,
                "timestamp": item.get("timestamp"),
                "attachments": attachments,
                "no_response_required": no_response,
                "evidence_refs": [],
            })
        return messages

    raw = source.read_text(encoding="utf-8").replace("\r\n", "\n").replace("\r", "\n")
    blocks = [block.strip("\n") for block in re.split(r"\n\s*\n", raw) if block.strip()]
    if not blocks:
        raise ValueError("TXT input is empty")
    messages = []
    for block in blocks:
        if block.startswith("USER:"):
            role, content = "user", block[len("USER:"):].lstrip()
        elif block.startswith("ASSISTANT:"):
            role, content = "assistant", block[len("ASSISTANT:"):].lstrip()
        else:
            raise ValueError("TXT blocks must start with USER: or ASSISTANT:")
        messages.append({
            "role": role,
            "content": content,
            "timestamp": None,
            "attachments": [],
            "no_response_required": False,
            "evidence_refs": [],
        })
    return messages


def deterministic_ids(messages: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], Dict[int, str]]:
    response_counter = 0
    prompt_map: Dict[int, str] = {}
    for index, message in enumerate(messages):
        prompt_id = f"P{index + 1:06d}"
        prompt_map[index] = prompt_id
        if message["role"] == "assistant":
            response_counter += 1
            message["response_id"] = f"R{response_counter:06d}"
        else:
            message["response_id"] = None
        message["prompt_id"] = prompt_id
        message["chat_index"] = index
    return messages, prompt_map


def extract_session_header(messages: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not messages:
        return None
    first = _norm_text(messages[0].get("content", ""))
    lines = first.split("\n")
    start = None
    version = None
    for index, line in enumerate(lines):
        match = SESSION_HEADER_RE.match(line.strip())
        if match:
            start, version = index, match.group("ver")
            break
    if start is None:
        return None
    header_lines = [lines[start].rstrip()]
    parsed: Dict[str, Any] = {}
    unknown: Dict[str, str] = {}
    for line in lines[start + 1:]:
        if not line.strip() or ":" not in line:
            break
        header_lines.append(line.rstrip())
        key, value = line.split(":", 1)
        key_norm = HEADER_KEY_ALIASES.get(_norm_key(key), _norm_key(key))
        value = value.strip()
        parsed[key_norm] = _split_list(value) if key_norm == "assumptions" else value
        if key_norm not in HEADER_FIELD_ORDER:
            unknown[key_norm] = value
    normalized = {key: parsed.get(key, [] if key == "assumptions" else "") for key in HEADER_FIELD_ORDER}
    return {
        "schema_version": f"session_header.v{version}",
        "header_version": version,
        "raw_text": "\n".join(header_lines).strip() + "\n",
        "fields": normalized,
        "unknown_fields": unknown,
        "source": {
            "chat_index": messages[0].get("chat_index"),
            "prompt_id": messages[0].get("prompt_id"),
            "response_id": messages[0].get("response_id"),
            "message_hash": sha256_text(first),
        },
    }


def build_prompt_log(messages: List[Dict[str, Any]], scope_tag: str) -> List[Dict[str, Any]]:
    result = []
    for message in messages:
        text = _norm_text(message["content"])
        result.append({
            "prompt_id": message["prompt_id"],
            "role": message["role"],
            "timestamp": message.get("timestamp"),
            "chat_index": message["chat_index"],
            "message_text": text,
            "message_hash": sha256_text(text),
            "scope_tag": scope_tag,
        })
    return result


def build_prompt_response_map(messages: List[Dict[str, Any]]) -> Dict[str, Any]:
    mappings: List[Dict[str, Any]] = []
    pending_users: List[str] = []
    no_response_required: List[str] = []
    unlinked_responses: List[str] = []
    for message in messages:
        if message["role"] == "user":
            if message.get("no_response_required"):
                no_response_required.append(message["prompt_id"])
            else:
                pending_users.append(message["prompt_id"])
            continue
        if not pending_users:
            unlinked_responses.append(message["response_id"])
            continue
        mappings.append({
            "response_id": message["response_id"],
            "responds_to_prompt_ids": list(pending_users),
            "response_text_hash": sha256_text(message["content"]),
            "response_scope_note": "all pending user prompts since prior assistant response",
        })
        pending_users.clear()
    return {
        "mappings": mappings,
        "no_response_required_prompt_ids": no_response_required,
        "unanswered_prompt_ids": pending_users,
        "unlinked_response_ids": unlinked_responses,
    }


def _copy_explicit_file(source: str | Path, evidence_dir: Path) -> Path:
    source_path = Path(source).resolve(strict=True)
    if not source_path.is_file() or source_path.is_symlink():
        raise AMCSSecurityError(f"evidence source is not a regular file: {source_path}")
    destination = evidence_dir / source_path.name
    stem, suffix, counter = destination.stem, destination.suffix, 1
    while destination.exists():
        destination = evidence_dir / f"{stem}_{counter}{suffix}"
        counter += 1
    shutil.copy2(source_path, destination)
    return destination


def copy_evidence(
    odt_path: Optional[str],
    messages: List[Dict[str, Any]],
    attachments_root: Optional[str],
    evidence_dir: str | Path,
) -> List[str]:
    evidence = Path(evidence_dir)
    evidence.mkdir(parents=True, exist_ok=True)
    copied: List[str] = []
    if odt_path:
        copied.append(str(_copy_explicit_file(odt_path, evidence)))
    attachments = [a for message in messages for a in (message.get("attachments") or [])]
    if attachments and not attachments_root:
        raise AMCSSecurityError("message attachments require --attachments-root")
    if attachments_root:
        root = Path(attachments_root).resolve(strict=True)
        if not root.is_dir():
            raise AMCSSecurityError("attachments root must be a directory")
        for message in messages:
            refs: List[str] = []
            for attachment in message.get("attachments") or []:
                path = Path(attachment)
                if path.is_absolute():
                    raise AMCSSecurityError("message attachment paths must be relative to --attachments-root")
                source = _resolved_child(root, root / path)
                if not source.is_file() or source.is_symlink():
                    raise AMCSSecurityError(f"attachment missing or not a regular file: {attachment}")
                destination = _copy_explicit_file(source, evidence)
                copied.append(str(destination))
                refs.append(f"evidence/{destination.name}")
            message["evidence_refs"] = refs
    return copied


def build_messages_matrix(messages: List[Dict[str, Any]], out_dir: str | Path) -> Tuple[str, str]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    csv_path, jsonl_path = out / "messages.csv", out / "messages.jsonl"
    fields = [
        "matrix_row_id", "row_type", "role", "chat_index", "prompt_id", "response_id", "timestamp",
        "observation_text", "message_hash", "source_prompt_ids", "source_response_ids",
        "source_message_hashes", "source_artifact_refs",
    ]
    rows = []
    for index, message in enumerate(messages, start=1):
        text, digest = _norm_text(message["content"]), sha256_text(message["content"])
        rows.append({
            "matrix_row_id": f"MMSG{index:06d}",
            "row_type": "message",
            "role": message["role"],
            "chat_index": message["chat_index"],
            "prompt_id": message["prompt_id"],
            "response_id": message["response_id"],
            "timestamp": message.get("timestamp"),
            "observation_text": text,
            "message_hash": digest,
            "source_prompt_ids": [message["prompt_id"]],
            "source_response_ids": [message["response_id"]] if message["response_id"] else [],
            "source_message_hashes": [digest],
            "source_artifact_refs": list(message.get("evidence_refs", [])),
        })
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            flat = dict(row)
            for key in ("source_prompt_ids", "source_response_ids", "source_message_hashes", "source_artifact_refs"):
                flat[key] = ";".join(row[key])
            flat["response_id"] = flat["response_id"] or ""
            flat["timestamp"] = flat["timestamp"] or ""
            writer.writerow(flat)
    with jsonl_path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, allow_nan=False) + "\n")
    return str(csv_path), str(jsonl_path)


def _source_provenance(messages: List[Dict[str, Any]]) -> Tuple[List[str], List[str], List[str]]:
    return (
        [m["prompt_id"] for m in messages],
        [m["response_id"] for m in messages if m.get("response_id")],
        [sha256_text(m["content"]) for m in messages],
    )


def build_tensor_summary(cell: Path, messages: List[Dict[str, Any]]) -> None:
    rows = [f"MMSG{index:06d}" for index in range(1, len(messages) + 1)]
    prompt_ids, response_ids, message_hashes = _source_provenance(messages)
    _write_json(cell / "data" / "tensors" / "summary.json", {
        "tensor_id": "TENSOR_MESSAGE_COUNTS",
        "allowed_operation": "count",
        "source_matrix_rows": rows,
        "source_prompt_ids": prompt_ids,
        "source_response_ids": response_ids,
        "source_message_hashes": message_hashes,
        "metrics": {
            "message_count": len(messages),
            "user_message_count": sum(1 for m in messages if m["role"] == "user"),
            "assistant_message_count": sum(1 for m in messages if m["role"] == "assistant"),
        },
    })


def build_session_header_artifacts(cell: Path, header: Dict[str, Any]) -> None:
    data, matrices, casefiles = cell / "data", cell / "data" / "matrices", cell / "casefiles"
    matrices.mkdir(parents=True, exist_ok=True)
    casefiles.mkdir(parents=True, exist_ok=True)
    _write_json(data / "session_header.json", header)
    source = header.get("source", {})
    fields = header.get("fields", {})
    row = {
        "matrix_row_id": "MSH000001", "row_type": "session_header", "header_version": header.get("header_version") or "",
        "domain": fields.get("domain", ""), "primary_question": fields.get("primary_question", ""), "scope": fields.get("scope", ""),
        "assumptions": "; ".join(fields.get("assumptions", []) or []), "constraints": fields.get("constraints", ""),
        "desired_output": fields.get("desired_output", ""), "stop_condition": fields.get("stop_condition", ""),
        "follow_ups": fields.get("follow_ups", ""), "sensitivity": fields.get("sensitivity", ""), "exclusions": fields.get("exclusions", ""),
        "source_prompt_ids": source.get("prompt_id", ""), "source_response_ids": source.get("response_id", ""),
        "source_message_hashes": source.get("message_hash", ""),
    }
    with (matrices / "session_header.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(row))
        writer.writeheader()
        writer.writerow(row)
    jrow = dict(row)
    for key in ("source_prompt_ids", "source_response_ids", "source_message_hashes"):
        jrow[key] = [row[key]] if row[key] else []
    (matrices / "session_header.jsonl").write_text(json.dumps(jrow, ensure_ascii=False, allow_nan=False) + "\n", encoding="utf-8")
    lines = [
        "# Case File: Session Header", "", "## Narrative meaning and boundaries",
        "FIRST-ORDER capture of the optional session-header block only; it does not infer facts beyond the source text.", "",
        "## Schema references", "- `data/session_header.json` (runtime structure)", "- `data/matrices/session_header.csv`", "",
        "## Provenance", f"- source_prompt_ids: {source.get('prompt_id', '')}", f"- source_response_ids: {source.get('response_id', '') or ''}",
        f"- source_message_hashes: {source.get('message_hash', '')}", "", "## Cross-links", "- `casefiles/CF_MESSAGES.md`", "- `data/case_study_map.json`", "",
        "## Known gaps / TODOs", "- Header parsing records unknown fields but does not interpret them.", "", "## Header (verbatim)", "```",
        (header.get("raw_text") or "").rstrip("\n"), "```",
    ]
    (casefiles / "CF_SESSION_HEADER.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def build_case_files(cell: Path, messages: List[Dict[str, Any]], scope: str, primary_source: str) -> None:
    path = cell / "casefiles" / "CF_MESSAGES.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    prompt_ids = [m["prompt_id"] for m in messages]
    response_ids = [m["response_id"] for m in messages if m["response_id"]]
    hashes = [sha256_text(m["content"]) for m in messages]
    path.write_text(
        "# Case File: Messages Matrix\n\n## Narrative meaning and boundaries\n"
        f"Canonical narrative anchor for the FIRST-ORDER chat-message matrix within scope `{scope}`. This case file records what the messages are and where they came from; it does not infer hidden intent or elevate derived artifacts.\n\n"
        "## Schema references\n- `data/matrices/messages.csv`\n- `data/matrices/messages.jsonl`\n- `data/prompt_log.json`\n\n"
        f"## Provenance\n- primary_narrative_source: {primary_source}\n- source_prompt_ids: {';'.join(prompt_ids)}\n- source_response_ids: {';'.join(response_ids)}\n- source_message_hashes: {';'.join(hashes)}\n\n"
        "## Cross-links\n- `data/case_study_map.json`\n- `data/tensors/summary.json`\n- `cell_index.json`\n\n"
        "## Known gaps / TODOs\n- The sealing pass does not infer entities, topics, or latent claims.\n",
        encoding="utf-8",
    )


def build_case_study_outputs(cell: Path, messages: List[Dict[str, Any]], header: Optional[Dict[str, Any]]) -> None:
    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []
    nodes.append({
        "node_id": "NCF000001", "node_type": "case_file", "label": "CF_MESSAGES",
        "source_prompt_ids": [messages[0]["prompt_id"]], "source_response_ids": [],
        "source_message_hashes": [sha256_text(messages[0]["content"])],
    })
    last_user = None
    edge_counter = 0
    for index, message in enumerate(messages, start=1):
        node_id, digest = f"NMSG{index:06d}", sha256_text(message["content"])
        nodes.append({
            "node_id": node_id, "node_type": "evidence_item", "label": f"{message['role']}@{message['prompt_id']}",
            "source_prompt_ids": [message["prompt_id"]],
            "source_response_ids": [message["response_id"]] if message["response_id"] else [],
            "source_message_hashes": [digest],
        })
        edge_counter += 1
        edges.append({
            "edge_id": f"E{edge_counter:06d}", "from_node_id": "NCF000001", "to_node_id": node_id,
            "edge_type": "references", "edge_epistemic_class": "relational",
            "source_prompt_ids": [message["prompt_id"]],
            "source_response_ids": [message["response_id"]] if message["response_id"] else [],
            "source_message_hashes": [digest],
        })
        if message["role"] == "user":
            last_user = node_id
        elif last_user:
            edge_counter += 1
            edges.append({
                "edge_id": f"E{edge_counter:06d}", "from_node_id": node_id, "to_node_id": last_user,
                "edge_type": "responds_to", "edge_epistemic_class": "relational",
                "source_prompt_ids": [message["prompt_id"]], "source_response_ids": [message["response_id"]],
                "source_message_hashes": [digest],
            })
    if header:
        source = header.get("source", {})
        nodes.append({
            "node_id": "NCF000002", "node_type": "case_file", "label": "CF_SESSION_HEADER",
            "source_prompt_ids": [source["prompt_id"]] if source.get("prompt_id") else [], "source_response_ids": [],
            "source_message_hashes": [source["message_hash"]] if source.get("message_hash") else [],
        })
        edge_counter += 1
        edges.append({
            "edge_id": f"E{edge_counter:06d}", "from_node_id": "NCF000002", "to_node_id": "NCF000001",
            "edge_type": "references", "edge_epistemic_class": "relational",
            "source_prompt_ids": [source["prompt_id"]] if source.get("prompt_id") else [],
            "source_response_ids": [], "source_message_hashes": [source["message_hash"]] if source.get("message_hash") else [],
        })
    _write_json(cell / "data" / "case_study_map.json", {"nodes": nodes, "edges": edges})
    node_fields = ["node_id", "node_type", "label", "source_prompt_ids", "source_response_ids", "source_message_hashes"]
    with (cell / "data" / "case_study_nodes.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=node_fields)
        writer.writeheader()
        for node in nodes:
            row = dict(node)
            for key in node_fields[3:]:
                row[key] = ";".join(row.get(key, []))
            writer.writerow(row)
    edge_fields = [
        "edge_id", "from_node_id", "to_node_id", "edge_type", "edge_epistemic_class",
        "source_prompt_ids", "source_response_ids", "source_message_hashes",
    ]
    with (cell / "data" / "case_study_edges.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=edge_fields)
        writer.writeheader()
        for edge in edges:
            row = dict(edge)
            for key in edge_fields[5:]:
                row[key] = ";".join(row.get(key, []))
            writer.writerow(row)


def write_cell_readme(cell: Path, scope: str, has_header: bool) -> None:
    order = [
        "- `casefiles/CF_MESSAGES.md`", "- `data/prompt_log.json`", "- `data/matrices/messages.csv`",
        "- `data/case_study_map.json`", "- `data/tensors/summary.json`", "- `cell_index.json`",
    ]
    if has_header:
        order.insert(0, "- `casefiles/CF_SESSION_HEADER.md`")
    text = (
        "# AMCS Memory Cell (INTERNAL)\n\n## Read order\n" + "\n".join(order) +
        "\n\n## Authority rules\n- Narrative is canonical for meaning.\n- Matrices are FIRST-ORDER only.\n"
        "- Graph relationships are traversal aids and cannot override narrative.\n- Tensor summary is mechanical and cannot define truth.\n"
        "- Derived indexes do not define truth.\n\n## What this is NOT\n- Not a model instruction channel.\n- Not proof that every derived interpretation is true.\n"
        "- Not authorization for external side effects.\n- Not a public/redacted export profile.\n\nScope: " + scope + "\n"
    )
    (cell / "README.md").write_text(text, encoding="utf-8")


def copy_reference_schemas(cell: Path) -> None:
    source_root = Path(__file__).resolve().parents[1] / "schemas"
    destination = cell / "schemas"
    destination.mkdir(parents=True, exist_ok=True)
    for name in AMCS_SCHEMA_NAMES:
        source = source_root / name
        if not source.is_file():
            raise AMCSValidationError(f"required reference schema missing: {name}")
        shutil.copy2(source, destination / name)


def _verify_graph_references(cell: Path) -> List[str]:
    errors: List[str] = []
    try:
        graph = json.loads((cell / "data" / "case_study_map.json").read_text(encoding="utf-8"))
        nodes = graph["nodes"]
        edges = graph["edges"]
        node_ids = [n["node_id"] for n in nodes]
        edge_ids = [e["edge_id"] for e in edges]
        if len(node_ids) != len(set(node_ids)):
            errors.append("duplicate case-study node_id")
        if len(edge_ids) != len(set(edge_ids)):
            errors.append("duplicate case-study edge_id")
        known = set(node_ids)
        for edge in edges:
            if edge["from_node_id"] not in known:
                errors.append(f"edge from unknown node: {edge['edge_id']}")
            if edge["to_node_id"] not in known:
                errors.append(f"edge to unknown node: {edge['edge_id']}")
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
        errors.append(f"case-study referential-integrity error: {type(exc).__name__}")
    return errors


def _preseal_errors(cell: Path, prompt_map: Dict[str, Any], header: Optional[Dict[str, Any]]) -> List[str]:
    errors: List[str] = []
    required = [
        "data/prompt_log.json", "data/prompt_response_map.json", "data/matrices/messages.csv", "data/matrices/messages.jsonl",
        "data/case_study_map.json", "data/case_study_nodes.csv", "data/case_study_edges.csv", "data/tensors/summary.json",
        "casefiles/CF_MESSAGES.md", "README.md", "schemas/case_study_map.schema.json", "schemas/cell_index.schema.json",
        "schemas/seal_receipt.schema.json", "schemas/tensor_summary.schema.json",
    ]
    for rel in required:
        if not (cell / rel).is_file():
            errors.append(f"missing required artifact: {rel}")
    if header:
        for rel in ("data/session_header.json", "data/matrices/session_header.csv", "data/matrices/session_header.jsonl", "casefiles/CF_SESSION_HEADER.md"):
            if not (cell / rel).is_file():
                errors.append(f"missing session header artifact: {rel}")
    if prompt_map.get("unanswered_prompt_ids"):
        errors.append("unanswered user prompts without no_response_required: " + ",".join(prompt_map["unanswered_prompt_ids"]))
    if prompt_map.get("unlinked_response_ids"):
        errors.append("assistant responses without prompt linkage: " + ",".join(prompt_map["unlinked_response_ids"]))
    errors.extend(_verify_graph_references(cell))
    return errors


def write_verification_log(cell: Path, errors: List[str]) -> None:
    logs = cell / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    lines = [
        f"AMCS runtime {__version__}", f"timestamp={_now()}", "phase=preseal",
        "checks=required-artifacts,prompt-response-causality,case-study-referential-integrity",
        f"result={'PASS' if not errors else 'FAIL'}",
    ]
    lines.extend(f"error={error}" for error in errors)
    (logs / "verification.log").write_text("\n".join(lines) + "\n", encoding="utf-8")


_MANIFEST_EXCLUDES = {
    "manifests/file_hashes.sha256",
    "manifests/seal_receipt.json",
    "manifests/cell_root.json",
    "cell_index.json",
}


def _iter_regular_files(root: Path) -> Iterable[Path]:
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise AMCSSecurityError(f"symlink forbidden in cell: {path}")
        if path.is_file():
            yield path


def build_file_hashes_manifest(cell: Path) -> Path:
    manifest = cell / "manifests" / "file_hashes.sha256"
    manifest.parent.mkdir(parents=True, exist_ok=True)
    lines = []
    for path in _iter_regular_files(cell):
        rel = path.relative_to(cell).as_posix()
        if rel not in _MANIFEST_EXCLUDES:
            lines.append(f"{sha256_file(path)}  {rel}")
    manifest.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return manifest


def _provenance_from_cell(cell: Path) -> Tuple[List[str], List[str], List[str]]:
    prompt_log = json.loads((cell / "data" / "prompt_log.json").read_text(encoding="utf-8"))
    prompt_map = json.loads((cell / "data" / "prompt_response_map.json").read_text(encoding="utf-8"))
    prompt_ids = [entry["prompt_id"] for entry in prompt_log]
    response_ids = [mapping["response_id"] for mapping in prompt_map.get("mappings", [])]
    message_hashes = [entry["message_hash"] for entry in prompt_log]
    return prompt_ids, response_ids, message_hashes


def build_cell_index(
    cell: Path,
    cell_id: str,
    case_id: str,
    manifest_hash: str,
    header: Optional[Dict[str, Any]],
    evidence: List[str],
    parent_hash: Optional[str],
    delta_type: Optional[str],
) -> Path:
    domain = str(header.get("fields", {}).get("domain", "")) if header else ""
    prompt_ids, response_ids, message_hashes = _provenance_from_cell(cell)
    obj = {
        "cell_id": cell_id,
        "content_hash": manifest_hash,
        "created_at": _now(),
        "domains": [domain] if domain else [],
        "topics": [],
        "entities": [],
        "claims": [],
        "evidence_types": sorted({"chat", *[Path(p).suffix.lower().lstrip(".") or "file" for p in evidence]}),
        "parent_cell_hashes": [parent_hash] if parent_hash else [],
        "delta_type": delta_type,
        "case_study_id": case_id,
        "source_prompt_ids": prompt_ids,
        "source_response_ids": response_ids,
        "source_message_hashes": message_hashes,
    }
    path = cell / "cell_index.json"
    _write_json(path, obj)
    return path


def build_seal_receipt(
    cell: Path,
    scope: str,
    primary_source: str,
    case_id: str,
    cell_id: str,
    manifest_hash: str,
    parent_hash: Optional[str],
    delta_type: Optional[str],
) -> Path:
    receipt = {
        "genesis_prompt_verbatim": AMCS_INIT_SEED_DEFAULT,
        "scope": scope,
        "run_mode_note": f"INTERNAL profile; full crawl; no redactions; runtime={__version__}",
        "primary_narrative_source": primary_source,
        "case_study_id": case_id,
        "cell_id": cell_id,
        "content_hash": manifest_hash,
        "build_timestamp": _now(),
        "parent_cell_hash": parent_hash,
        "delta_type": delta_type,
    }
    path = cell / "manifests" / "seal_receipt.json"
    _write_json(path, receipt)
    return path


def _parse_seal_key(value: Optional[str]) -> Optional[bytes]:
    if value is None:
        return None
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", value):
        raise AMCSSecurityError("seal key must be exactly 64 hexadecimal characters")
    return bytes.fromhex(value)


def _root_binding_payload(
    cell_id: str,
    case_id: str,
    manifest_hash: str,
    receipt_hash: str,
    index_hash: str,
    parent_hash: Optional[str],
    delta_type: Optional[str],
    authentication_alg: str,
) -> Dict[str, Any]:
    return {
        "root_version": 1,
        "cell_id": cell_id,
        "case_study_id": case_id,
        "content_manifest_hash": manifest_hash,
        "seal_receipt_hash": receipt_hash,
        "cell_index_hash": index_hash,
        "parent_cell_hash": parent_hash,
        "delta_type": delta_type,
        "authentication_alg": authentication_alg,
    }


def build_cell_root(
    cell: Path,
    manifest: Path,
    receipt: Path,
    index: Path,
    cell_id: str,
    case_id: str,
    parent_hash: Optional[str],
    delta_type: Optional[str],
    seal_key: Optional[bytes],
) -> Path:
    alg = "HMAC-SHA256" if seal_key is not None else "NONE"
    payload = _root_binding_payload(
        cell_id,
        case_id,
        sha256_file(manifest),
        sha256_file(receipt),
        sha256_file(index),
        parent_hash,
        delta_type,
        alg,
    )
    root_hash = canonical_hash(payload)
    obj = dict(payload)
    obj["root_hash"] = root_hash
    if seal_key is None:
        obj["root_mac"] = None
    else:
        obj["root_mac"] = hmac.new(
            seal_key,
            _canonical_bytes({**payload, "root_hash": root_hash}),
            hashlib.sha256,
        ).hexdigest()
    path = cell / "manifests" / "cell_root.json"
    _write_json(path, obj)
    return path


def _verify_root(cell: Path, errors: List[str], seal_key: Optional[bytes]) -> None:
    try:
        root = json.loads((cell / "manifests" / "cell_root.json").read_text(encoding="utf-8"))
        receipt = json.loads((cell / "manifests" / "seal_receipt.json").read_text(encoding="utf-8"))
        index = json.loads((cell / "cell_index.json").read_text(encoding="utf-8"))
        payload = {
            key: root[key]
            for key in (
                "root_version", "cell_id", "case_study_id", "content_manifest_hash",
                "seal_receipt_hash", "cell_index_hash", "parent_cell_hash", "delta_type",
                "authentication_alg",
            )
        }
        computed_root = canonical_hash(payload)
        if computed_root != root.get("root_hash"):
            errors.append("cell root hash mismatch")
        if sha256_file(cell / "manifests" / "file_hashes.sha256") != root.get("content_manifest_hash"):
            errors.append("cell root manifest binding mismatch")
        if sha256_file(cell / "manifests" / "seal_receipt.json") != root.get("seal_receipt_hash"):
            errors.append("cell root receipt binding mismatch")
        if sha256_file(cell / "cell_index.json") != root.get("cell_index_hash"):
            errors.append("cell root index binding mismatch")

        # A recomputed root hash must not let an attacker rewrite redundant
        # identity/lineage metadata independently of the receipt and index.
        if root.get("cell_id") != receipt.get("cell_id") or root.get("cell_id") != index.get("cell_id"):
            errors.append("cell root cell_id metadata mismatch")
        if root.get("case_study_id") != receipt.get("case_study_id") or root.get("case_study_id") != index.get("case_study_id"):
            errors.append("cell root case_study_id metadata mismatch")
        if root.get("delta_type") != receipt.get("delta_type") or root.get("delta_type") != index.get("delta_type"):
            errors.append("cell root delta_type metadata mismatch")
        expected_parent = receipt.get("parent_cell_hash")
        if root.get("parent_cell_hash") != expected_parent:
            errors.append("cell root parent_cell_hash metadata mismatch")
        index_parents = index.get("parent_cell_hashes", [])
        if index_parents != ([expected_parent] if expected_parent else []):
            errors.append("cell root/index parent lineage metadata mismatch")

        alg = root.get("authentication_alg")
        if seal_key is not None and alg != "HMAC-SHA256":
            errors.append("verification key supplied but cell root is not authenticated")
        elif alg == "HMAC-SHA256":
            if seal_key is None:
                errors.append("authenticated cell root requires verification key")
            else:
                expected = hmac.new(
                    seal_key,
                    _canonical_bytes({**payload, "root_hash": computed_root}),
                    hashlib.sha256,
                ).hexdigest()
                claimed = root.get("root_mac")
                if not isinstance(claimed, str) or not hmac.compare_digest(claimed, expected):
                    errors.append("cell root MAC mismatch")
        elif alg == "NONE":
            if root.get("root_mac") is not None:
                errors.append("unauthenticated root must not carry MAC")
        else:
            errors.append("unsupported cell root authentication algorithm")
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        errors.append(f"invalid cell root: {type(exc).__name__}")


def _verify_matrix_evidence_refs(cell: Path, errors: List[str]) -> None:
    try:
        with (cell / "data" / "matrices" / "messages.jsonl").open("r", encoding="utf-8") as handle:
            for line_number, raw in enumerate(handle, start=1):
                if not raw.strip():
                    continue
                row = json.loads(raw)
                for ref in row.get("source_artifact_refs", []):
                    pure = PurePosixPath(ref)
                    if pure.is_absolute() or ".." in pure.parts:
                        errors.append(f"unsafe matrix evidence ref at line {line_number}: {ref}")
                        continue
                    target = _resolved_child(cell, cell.joinpath(*pure.parts))
                    if not target.is_file() or target.is_symlink():
                        errors.append(f"missing matrix evidence ref at line {line_number}: {ref}")
    except (OSError, TypeError, json.JSONDecodeError) as exc:
        errors.append(f"matrix evidence-reference verification error: {type(exc).__name__}")


def _verify_direct_provenance(
    prompt_log: List[Dict[str, Any]],
    prompt_map: Dict[str, Any],
    tensor: Dict[str, Any],
    index: Dict[str, Any],
    errors: List[str],
) -> None:
    try:
        prompt_ids = [entry["prompt_id"] for entry in prompt_log]
        response_ids = [mapping["response_id"] for mapping in prompt_map.get("mappings", [])]
        message_hashes = [entry["message_hash"] for entry in prompt_log]
        for name, obj in (("tensor", tensor), ("cell index", index)):
            if obj.get("source_prompt_ids") != prompt_ids:
                errors.append(f"{name} source_prompt_ids mismatch")
            if obj.get("source_response_ids") != response_ids:
                errors.append(f"{name} source_response_ids mismatch")
            if obj.get("source_message_hashes") != message_hashes:
                errors.append(f"{name} source_message_hashes mismatch")
    except (KeyError, TypeError) as exc:
        errors.append(f"direct provenance verification error: {type(exc).__name__}")


def verify_cell_dir(cell_dir: str | Path, *, seal_key: Optional[bytes] = None) -> Tuple[bool, List[str]]:
    cell = Path(cell_dir)
    errors: List[str] = []
    manifest = cell / "manifests" / "file_hashes.sha256"
    receipt_path = cell / "manifests" / "seal_receipt.json"
    for rel in (
        "manifests/file_hashes.sha256", "manifests/seal_receipt.json", "manifests/cell_root.json",
        "cell_index.json", "logs/verification.log",
    ):
        if not (cell / rel).is_file():
            errors.append(f"missing required artifact: {rel}")
    if errors:
        return False, errors

    listed: set[str] = set()
    for raw in manifest.read_text(encoding="utf-8").splitlines():
        if not raw.strip():
            continue
        match = re.fullmatch(r"([a-f0-9]{64})  (.+)", raw)
        if not match:
            errors.append(f"bad hash line: {raw}")
            continue
        expected, rel = match.groups()
        pure = PurePosixPath(rel)
        if pure.is_absolute() or ".." in pure.parts:
            errors.append(f"unsafe manifest path: {rel}")
            continue
        if rel in listed:
            errors.append(f"duplicate manifest path: {rel}")
            continue
        listed.add(rel)
        full = _resolved_child(cell, cell.joinpath(*pure.parts))
        if not full.is_file() or full.is_symlink():
            errors.append(f"missing/non-regular manifest file: {rel}")
        elif sha256_file(full) != expected:
            errors.append(f"hash mismatch: {rel}")
    actual = {
        p.relative_to(cell).as_posix()
        for p in _iter_regular_files(cell)
        if p.relative_to(cell).as_posix() not in _MANIFEST_EXCLUDES
    }
    for rel in sorted(actual - listed):
        errors.append(f"unlisted file: {rel}")
    for rel in sorted(listed - actual):
        errors.append(f"manifest-only file: {rel}")

    required = [
        "data/prompt_log.json", "data/prompt_response_map.json", "data/matrices/messages.csv", "data/matrices/messages.jsonl",
        "data/case_study_map.json", "data/case_study_nodes.csv", "data/case_study_edges.csv", "data/tensors/summary.json",
        "casefiles/CF_MESSAGES.md", "README.md", "schemas/case_study_map.schema.json", "schemas/cell_index.schema.json",
        "schemas/prompt_log.schema.json", "schemas/prompt_response_map.schema.json", "schemas/tensor_summary.schema.json",
    ]
    for rel in required:
        if not (cell / rel).is_file():
            errors.append(f"missing required artifact: {rel}")

    prompt_log: List[Dict[str, Any]] = []
    prm: Dict[str, Any] = {}
    try:
        prompt_log = json.loads((cell / "data" / "prompt_log.json").read_text(encoding="utf-8"))
        prm = json.loads((cell / "data" / "prompt_response_map.json").read_text(encoding="utf-8"))
        user_ids = {e["prompt_id"] for e in prompt_log if e.get("role") == "user"}
        mapped = {pid for m in prm.get("mappings", []) for pid in m.get("responds_to_prompt_ids", [])}
        no_response = set(prm.get("no_response_required_prompt_ids", []))
        unanswered = set(prm.get("unanswered_prompt_ids", []))
        unlinked = set(prm.get("unlinked_response_ids", []))
        if unanswered:
            errors.append("unanswered prompt IDs present in sealed cell")
        if unlinked:
            errors.append("unlinked assistant response IDs present in sealed cell")
        if user_ids != mapped | no_response:
            errors.append("prompt causality coverage mismatch")
        assistants = sum(1 for e in prompt_log if e.get("role") == "assistant")
        if assistants != len(prm.get("mappings", [])):
            errors.append("assistant response mapping coverage mismatch")
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
        errors.append(f"causality verification error: {type(exc).__name__}")

    errors.extend(_verify_graph_references(cell))
    _verify_matrix_evidence_refs(cell, errors)

    tensor: Dict[str, Any] = {}
    try:
        tensor = json.loads((cell / "data" / "tensors" / "summary.json").read_text(encoding="utf-8"))
        rows = tensor.get("source_matrix_rows", [])
        if len(rows) != tensor.get("metrics", {}).get("message_count"):
            errors.append("tensor source-row count mismatch")
    except (OSError, TypeError, json.JSONDecodeError) as exc:
        errors.append(f"tensor verification error: {type(exc).__name__}")

    try:
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        index = json.loads((cell / "cell_index.json").read_text(encoding="utf-8"))
        if receipt.get("content_hash") != sha256_file(manifest):
            errors.append("seal receipt content_hash does not match manifest")
        if receipt.get("genesis_prompt_verbatim") != AMCS_INIT_SEED_DEFAULT:
            errors.append("mandatory genesis seed mismatch")
        if index.get("content_hash") != sha256_file(manifest):
            errors.append("cell index content_hash does not match manifest")
        if index.get("cell_id") != receipt.get("cell_id"):
            errors.append("cell index/receipt cell_id mismatch")
        if index.get("case_study_id") != receipt.get("case_study_id"):
            errors.append("cell index/receipt case_study_id mismatch")
        if index.get("delta_type") != receipt.get("delta_type"):
            errors.append("cell index/receipt delta_type mismatch")
        expected_parent = [receipt["parent_cell_hash"]] if receipt.get("parent_cell_hash") else []
        if index.get("parent_cell_hashes") != expected_parent:
            errors.append("cell index/receipt parent lineage mismatch")
        if prompt_log and prm and tensor:
            _verify_direct_provenance(prompt_log, prm, tensor, index, errors)
    except (OSError, TypeError, json.JSONDecodeError) as exc:
        errors.append(f"metadata verification error: {type(exc).__name__}")

    _verify_root(cell, errors, seal_key)
    return not errors, errors


def _validate_tar_member(member: tarfile.TarInfo) -> PurePosixPath:
    pure = PurePosixPath(member.name)
    if pure.is_absolute() or not pure.parts or ".." in pure.parts:
        raise AMCSSecurityError(f"unsafe archive path: {member.name}")
    if member.issym() or member.islnk() or member.isdev() or member.isfifo():
        raise AMCSSecurityError(f"archive link/special file forbidden: {member.name}")
    if not (member.isdir() or member.isfile()):
        raise AMCSSecurityError(f"unsupported archive member type: {member.name}")
    return pure


def safe_extract_tar(
    archive: str | Path,
    destination: str | Path,
    *,
    max_members: int = DEFAULT_MAX_ARCHIVE_MEMBERS,
    max_expanded_bytes: int = DEFAULT_MAX_EXPANDED_BYTES,
) -> None:
    if max_members < 1 or max_expanded_bytes < 1:
        raise ValueError("archive limits must be positive")
    dest = Path(destination).resolve()
    dest.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive, "r:*") as tar:
        members = tar.getmembers()
        if len(members) > max_members:
            raise AMCSSecurityError(f"archive member limit exceeded: {len(members)} > {max_members}")
        expanded = 0
        checked: List[Tuple[tarfile.TarInfo, PurePosixPath]] = []
        names: set[str] = set()
        for member in members:
            pure = _validate_tar_member(member)
            normalized = pure.as_posix()
            if normalized in names:
                raise AMCSSecurityError(f"duplicate archive member: {normalized}")
            names.add(normalized)
            if member.isfile():
                if member.size < 0:
                    raise AMCSSecurityError("negative archive member size")
                expanded += member.size
                if expanded > max_expanded_bytes:
                    raise AMCSSecurityError("archive expanded-size limit exceeded")
            checked.append((member, pure))
        for member, pure in checked:
            target = _resolved_child(dest, dest.joinpath(*pure.parts))
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            source = tar.extractfile(member)
            if source is None:
                raise AMCSSecurityError(f"unable to read archive member: {member.name}")
            with source, target.open("xb") as output:
                shutil.copyfileobj(source, output, length=1024 * 1024)


def _single_root(extracted: Path) -> Path:
    roots = list(extracted.iterdir())
    if len(roots) != 1 or not roots[0].is_dir() or roots[0].is_symlink():
        raise AMCSValidationError("cell archive must contain exactly one root directory")
    return roots[0]


def verify_archive(
    archive: str | Path,
    *,
    max_members: int = DEFAULT_MAX_ARCHIVE_MEMBERS,
    max_expanded_bytes: int = DEFAULT_MAX_EXPANDED_BYTES,
    seal_key: Optional[bytes] = None,
) -> Tuple[bool, List[str]]:
    try:
        with tempfile.TemporaryDirectory(prefix="amcs_verify_") as tmp:
            root = Path(tmp)
            safe_extract_tar(archive, root, max_members=max_members, max_expanded_bytes=max_expanded_bytes)
            return verify_cell_dir(_single_root(root), seal_key=seal_key)
    except (AMCSError, tarfile.TarError, OSError, ValueError) as exc:
        return False, [str(exc)]


def _create_tar_from_directory(source: Path, archive: Path, arcname: str) -> None:
    archive.parent.mkdir(parents=True, exist_ok=True)
    try:
        with archive.open("xb") as raw:
            with tarfile.open(fileobj=raw, mode="w:gz") as tar:
                tar.add(source, arcname=arcname, recursive=True)
            raw.flush()
            os.fsync(raw.fileno())
        try:
            fd = os.open(archive.parent, os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
        except OSError:
            pass
    except FileExistsError as exc:
        raise AMCSSecurityError(f"refusing to overwrite existing sealed artifact: {archive}") from exc
    except BaseException:
        archive.unlink(missing_ok=True)
        raise


def _parent_lineage(
    parent_cell: Optional[str],
    delta_type: Optional[str],
    parent_key: Optional[bytes],
    max_members: int,
    max_expanded_bytes: int,
) -> Tuple[Optional[str], Optional[str]]:
    if (parent_cell is None) != (delta_type is None):
        raise AMCSValidationError("delta-type and parent-cell must be provided together")
    if parent_cell is None:
        if parent_key is not None:
            raise AMCSValidationError("parent seal key requires --parent-cell")
        return None, None
    if delta_type not in ("additive", "corrective", "contextual"):
        raise AMCSValidationError("invalid delta-type")
    parent = Path(parent_cell).resolve(strict=True)
    ok, errors = verify_archive(
        parent,
        max_members=max_members,
        max_expanded_bytes=max_expanded_bytes,
        seal_key=parent_key,
    )
    if not ok:
        raise AMCSValidationError("parent cell failed verification: " + "; ".join(errors))
    with tempfile.TemporaryDirectory(prefix="amcs_parent_") as tmp:
        root = Path(tmp)
        safe_extract_tar(parent, root, max_members=max_members, max_expanded_bytes=max_expanded_bytes)
        parent_root = _single_root(root)
        try:
            index = json.loads((parent_root / "cell_index.json").read_text(encoding="utf-8"))
            case_id = index["case_study_id"]
        except (OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
            raise AMCSValidationError(f"invalid parent cell index:{type(exc).__name__}") from exc
        if not isinstance(case_id, str) or not case_id:
            raise AMCSValidationError("parent cell case_study_id is invalid")
    return sha256_file(parent), case_id


def _base_case_id(scope: str, primary_source: str, prompt_log: List[Dict[str, Any]], evidence: List[str]) -> str:
    evidence_binding = [{"name": Path(path).name, "sha256": sha256_file(path)} for path in sorted(evidence)]
    return "CASE_" + canonical_hash({
        "scope": scope,
        "primary_narrative_source": primary_source,
        "prompt_log": prompt_log,
        "evidence": evidence_binding,
    })[:16]


def seal(args: argparse.Namespace) -> str:
    cell_id = _validate_identifier(args.cell_name, "cell-name")
    out_root = Path(args.out_dir).resolve()
    out_root.mkdir(parents=True, exist_ok=True)
    final = _safe_output_path(out_root, f"{cell_id}.tar.gz")
    if final.exists():
        raise AMCSSecurityError(f"refusing to overwrite existing sealed cell: {final}")
    supplied_genesis = getattr(args, "genesis_prompt", None)
    if supplied_genesis not in (None, AMCS_INIT_SEED_DEFAULT):
        raise AMCSValidationError("AMCS v1.2.1 requires the fixed genesis seed verbatim")
    seal_key = _parse_seal_key(getattr(args, "seal_key_hex", None))
    parent_key = _parse_seal_key(getattr(args, "parent_seal_key_hex", None))
    max_members = getattr(args, "max_archive_members", DEFAULT_MAX_ARCHIVE_MEMBERS)
    max_expanded = getattr(args, "max_expanded_bytes", DEFAULT_MAX_EXPANDED_BYTES)
    parent_hash, inherited_case_id = _parent_lineage(
        getattr(args, "parent_cell", None),
        getattr(args, "delta_type", None),
        parent_key,
        max_members,
        max_expanded,
    )
    delta_type = getattr(args, "delta_type", None)
    explicit_case_id = getattr(args, "case_study_id", None)
    if explicit_case_id is not None:
        _validate_identifier(explicit_case_id, "case-study-id")
    if inherited_case_id is not None and explicit_case_id is not None and explicit_case_id != inherited_case_id:
        raise AMCSValidationError("delta case-study-id must match verified parent")

    messages = load_chat(args.input)
    messages, _ = deterministic_ids(messages)
    header = extract_session_header(messages) if getattr(args, "parse_session_header", True) else None
    scope = getattr(args, "scope", None) or "entire_chat"
    odt = getattr(args, "odt", None)
    primary_source = getattr(args, "primary_narrative_source", None) or ("odt" if odt else "chat")
    if primary_source in ("odt", "both") and not odt:
        raise AMCSValidationError("ODT primary narrative source requires --odt")

    with tempfile.TemporaryDirectory(prefix=f".{cell_id}.", dir=out_root) as tmp:
        cell = Path(tmp) / cell_id
        cell.mkdir()
        evidence = copy_evidence(odt, messages, getattr(args, "attachments_root", None), cell / "evidence")
        prompt_log = build_prompt_log(messages, scope)
        prompt_map = build_prompt_response_map(messages)
        case_id = inherited_case_id or explicit_case_id or _base_case_id(scope, primary_source, prompt_log, evidence)
        _write_json(cell / "data" / "prompt_log.json", prompt_log)
        _write_json(cell / "data" / "prompt_response_map.json", prompt_map)
        build_messages_matrix(messages, cell / "data" / "matrices")
        build_tensor_summary(cell, messages)
        if header:
            build_session_header_artifacts(cell, header)
        build_case_files(cell, messages, scope, primary_source)
        build_case_study_outputs(cell, messages, header)
        write_cell_readme(cell, scope, bool(header))
        copy_reference_schemas(cell)
        preseal = _preseal_errors(cell, prompt_map, header)
        write_verification_log(cell, preseal)
        if preseal:
            raise AMCSValidationError("preseal verification failed: " + "; ".join(preseal))
        manifest = build_file_hashes_manifest(cell)
        manifest_hash = sha256_file(manifest)
        index = build_cell_index(cell, cell_id, case_id, manifest_hash, header, evidence, parent_hash, delta_type)
        receipt = build_seal_receipt(cell, scope, primary_source, case_id, cell_id, manifest_hash, parent_hash, delta_type)
        build_cell_root(cell, manifest, receipt, index, cell_id, case_id, parent_hash, delta_type, seal_key)
        ok, errors = verify_cell_dir(cell, seal_key=seal_key)
        if not ok:
            raise AMCSValidationError("seal verification failed: " + "; ".join(errors))
        _create_tar_from_directory(cell, final, cell_id)
    return str(final)


def verify(args: argparse.Namespace) -> int:
    seal_key = _parse_seal_key(getattr(args, "seal_key_hex", None))
    ok, errors = verify_archive(
        args.cell,
        max_members=args.max_archive_members,
        max_expanded_bytes=args.max_expanded_bytes,
        seal_key=seal_key,
    )
    if ok:
        print("PASS")
        return 0
    print("FAIL")
    for error in errors:
        print("-", error)
    return 1


def assemble_supercell(args: argparse.Namespace) -> str:
    name = _validate_identifier(args.supercell_name, "supercell-name")
    out_root = Path(args.out_dir).resolve()
    out_root.mkdir(parents=True, exist_ok=True)
    final = _safe_output_path(out_root, f"{name}.tar.gz")
    if final.exists():
        raise AMCSSecurityError(f"refusing to overwrite existing supercell: {final}")
    seal_key = _parse_seal_key(getattr(args, "seal_key_hex", None))
    child_hashes: List[str] = []
    for cell_path in args.cells:
        ok, errors = verify_archive(
            cell_path,
            max_members=args.max_archive_members,
            max_expanded_bytes=args.max_expanded_bytes,
            seal_key=seal_key,
        )
        if not ok:
            raise AMCSValidationError(f"child cell failed verification: {cell_path}: {'; '.join(errors)}")
        child_hashes.append(sha256_file(cell_path))
    with tempfile.TemporaryDirectory(prefix=f".{name}.", dir=out_root) as tmp:
        root = Path(tmp) / name
        cells = root / "cells"
        cells.mkdir(parents=True)
        for index, cell_path in enumerate(args.cells, start=1):
            shutil.copy2(Path(cell_path).resolve(strict=True), cells / f"cell_{index:03d}.tar.gz")
        _write_json(root / "supercell_manifest.json", {
            "supercell_id": f"SC_{sha256_text(name)[:12]}",
            "assembly_timestamp": _now(),
            "assembly_reason": args.reason or "task-scoped assembly",
            "included_cell_hashes": child_hashes,
            "assembly_scope": args.scope,
            "assembly_mode": args.mode,
            "notes": args.notes or "",
        })
        _create_tar_from_directory(root, final, name)
    return str(final)


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)
    ps = sub.add_parser("seal")
    ps.add_argument("--input", required=True)
    ps.add_argument("--out-dir", required=True)
    ps.add_argument("--cell-name", required=True)
    ps.add_argument("--scope", default="entire_chat")
    ps.add_argument("--primary-narrative-source", default=None, choices=["odt", "chat", "both"])
    ps.add_argument("--odt", default=None)
    ps.add_argument("--attachments-root", default=None)
    ps.add_argument("--genesis-prompt", default=None)
    ps.add_argument("--seal-key-hex", default=None)
    ps.add_argument("--parent-cell", default=None)
    ps.add_argument("--parent-seal-key-hex", default=None)
    ps.add_argument("--delta-type", choices=["additive", "corrective", "contextual"], default=None)
    ps.add_argument("--case-study-id", default=None)
    ps.add_argument("--max-archive-members", type=int, default=DEFAULT_MAX_ARCHIVE_MEMBERS)
    ps.add_argument("--max-expanded-bytes", type=int, default=DEFAULT_MAX_EXPANDED_BYTES)
    group = ps.add_mutually_exclusive_group()
    group.add_argument("--parse-session-header", dest="parse_session_header", action="store_true", default=True)
    group.add_argument("--no-parse-session-header", dest="parse_session_header", action="store_false")

    pv = sub.add_parser("verify")
    pv.add_argument("--cell", required=True)
    pv.add_argument("--max-archive-members", type=int, default=DEFAULT_MAX_ARCHIVE_MEMBERS)
    pv.add_argument("--max-expanded-bytes", type=int, default=DEFAULT_MAX_EXPANDED_BYTES)
    pv.add_argument("--seal-key-hex", default=None)

    pa = sub.add_parser("assemble-supercell")
    pa.add_argument("--cells", nargs="+", required=True)
    pa.add_argument("--out-dir", required=True)
    pa.add_argument("--supercell-name", required=True)
    pa.add_argument("--scope", required=True)
    pa.add_argument("--mode", default="research", choices=["analysis", "research", "consolidation", "planning"])
    pa.add_argument("--reason", default=None)
    pa.add_argument("--notes", default=None)
    pa.add_argument("--seal-key-hex", default=None)
    pa.add_argument("--max-archive-members", type=int, default=DEFAULT_MAX_ARCHIVE_MEMBERS)
    pa.add_argument("--max-expanded-bytes", type=int, default=DEFAULT_MAX_EXPANDED_BYTES)

    args = parser.parse_args()
    try:
        if args.cmd == "seal":
            print(seal(args))
            return 0
        if args.cmd == "verify":
            return verify(args)
        if args.cmd == "assemble-supercell":
            print(assemble_supercell(args))
            return 0
        return 2
    except (AMCSError, OSError, ValueError, tarfile.TarError) as exc:
        print(f"ERROR: {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
