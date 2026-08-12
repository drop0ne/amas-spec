#!/usr/bin/env python3
"""AMCS Runtime (Reference Implementation) — v0.2.0.

Security-hardened AMCS v1.2.1 INTERNAL-profile runtime.

Properties added in v0.2.0:
- bounded, traversal-safe tar extraction with no links/special files
- strict cell/supercell identifier validation and output-root containment
- attachment-root containment
- fail-closed sealing: verification failure emits no cell bundle
- archive member/expanded-size limits
- child-cell verification before supercell assembly
"""
from __future__ import annotations

import argparse
import csv
import datetime
import hashlib
import json
import os
import re
import shutil
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterable, List, Optional, Tuple

__version__ = "0.2.0"

AMCS_INIT_SEED_DEFAULT = (
    "Promote to a case study, so I want you to do is to quantify the data into an indexable "
    "structure consisting of multiple case files that collectively create a matrix (basic) tensor "
    "(multidimensional). Scope: entire chat;"
)
IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
SESSION_HEADER_RE = re.compile(r"^\[AMCS_SESSION_HEADER\s+v(?P<ver>[0-9.]+)\]\s*$", re.IGNORECASE)
DEFAULT_MAX_ARCHIVE_MEMBERS = 10_000
DEFAULT_MAX_EXPANDED_BYTES = 512 * 1024 * 1024

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


def _norm_text(value: str) -> str:
    value = value.replace("\r\n", "\n").replace("\r", "\n")
    return "\n".join(line.rstrip() for line in value.split("\n"))


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


def load_chat(path: str | Path) -> List[Dict[str, Any]]:
    source = Path(path)
    if source.suffix.lower() == ".json":
        data = json.loads(source.read_text(encoding="utf-8"))
        if not isinstance(data, list):
            raise ValueError("JSON input must be a list of message objects")
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
            if not isinstance(attachments, list) or any(not isinstance(a, str) for a in attachments):
                raise ValueError(f"Message {index} attachments must be an array of strings")
            messages.append({"role": role, "content": content, "timestamp": item.get("timestamp"), "attachments": attachments})
        return messages

    raw = source.read_text(encoding="utf-8").replace("\r\n", "\n").replace("\r", "\n")
    blocks = [block.strip("\n") for block in re.split(r"\n\s*\n", raw) if block.strip()]
    messages = []
    for block in blocks:
        if block.startswith("USER:"):
            role, content = "user", block[len("USER:"):].lstrip()
        elif block.startswith("ASSISTANT:"):
            role, content = "assistant", block[len("ASSISTANT:"):].lstrip()
        else:
            raise ValueError("TXT blocks must start with USER: or ASSISTANT:")
        messages.append({"role": role, "content": content, "timestamp": None, "attachments": []})
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
        if key_norm == "sensitivity" and "exclusions:" in value.lower():
            left, right = re.split(r"(?i)exclusions:\s*", value, maxsplit=1)
            parsed["sensitivity"], parsed["exclusions"] = left.strip(), right.strip()
            continue
        parsed[key_norm] = _split_list(value) if key_norm == "assumptions" else value
        if key_norm not in HEADER_FIELD_ORDER:
            unknown[key_norm] = value
    normalized = {key: parsed.get(key, [] if key == "assumptions" else "") for key in HEADER_FIELD_ORDER}
    return {
        "schema_version": f"session_header.v{version}", "header_version": version,
        "raw_text": "\n".join(header_lines).strip() + "\n", "fields": normalized,
        "unknown_fields": unknown,
        "source": {"chat_index": messages[0].get("chat_index"), "prompt_id": messages[0].get("prompt_id"),
                   "response_id": messages[0].get("response_id"), "message_hash": sha256_text(first)},
    }


def build_prompt_log(messages: List[Dict[str, Any]], scope_tag: str) -> List[Dict[str, Any]]:
    result = []
    for message in messages:
        text = _norm_text(message["content"])
        result.append({"prompt_id": message["prompt_id"], "role": message["role"], "timestamp": message.get("timestamp"),
                       "chat_index": message["chat_index"], "message_text": text, "message_hash": sha256_text(text),
                       "scope_tag": scope_tag})
    return result


def build_prompt_response_map(messages: List[Dict[str, Any]]) -> Dict[str, Any]:
    mappings = []
    last_user: Optional[str] = None
    for message in messages:
        if message["role"] == "user":
            last_user = message["prompt_id"]
            continue
        responds_to = [last_user] if last_user else ([messages[0]["prompt_id"]] if messages else [])
        if responds_to:
            mappings.append({"response_id": message["response_id"], "responds_to_prompt_ids": responds_to,
                             "response_text_hash": sha256_text(message["content"]),
                             "response_scope_note": "nearest prior user prompt" if last_user else "no prior user prompt; anchored to first prompt"})
    return {"mappings": mappings}


def _copy_explicit_file(source: str | Path, evidence_dir: Path) -> Path:
    source_path = Path(source).resolve(strict=True)
    if not source_path.is_file():
        raise AMCSSecurityError(f"evidence source is not a regular file: {source_path}")
    destination = evidence_dir / source_path.name
    stem, suffix, counter = destination.stem, destination.suffix, 1
    while destination.exists():
        destination = evidence_dir / f"{stem}_{counter}{suffix}"
        counter += 1
    shutil.copy2(source_path, destination)
    return destination


def copy_evidence(odt_path: Optional[str], messages: List[Dict[str, Any]], attachments_root: Optional[str], evidence_dir: str | Path) -> List[str]:
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
        for attachment in attachments:
            path = Path(attachment)
            if path.is_absolute():
                raise AMCSSecurityError("message attachment paths must be relative to --attachments-root")
            source = _resolved_child(root, root / path)
            if not source.is_file():
                raise AMCSSecurityError(f"attachment missing or not a regular file: {attachment}")
            copied.append(str(_copy_explicit_file(source, evidence)))
    return copied


def _write_json(path: Path, obj: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def build_messages_matrix(messages: List[Dict[str, Any]], out_dir: str | Path) -> Tuple[str, str]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    csv_path, jsonl_path = out / "messages.csv", out / "messages.jsonl"
    fields = ["matrix_row_id", "row_type", "role", "chat_index", "prompt_id", "response_id", "timestamp",
              "observation_text", "message_hash", "source_prompt_ids", "source_response_ids", "source_message_hashes"]
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for index, message in enumerate(messages, start=1):
            text, digest = _norm_text(message["content"]), sha256_text(message["content"])
            writer.writerow({"matrix_row_id": f"MMSG{index:06d}", "row_type": "message", "role": message["role"],
                             "chat_index": message["chat_index"], "prompt_id": message["prompt_id"],
                             "response_id": message["response_id"] or "", "timestamp": message.get("timestamp") or "",
                             "observation_text": text, "message_hash": digest, "source_prompt_ids": message["prompt_id"],
                             "source_response_ids": message["response_id"] or "", "source_message_hashes": digest})
    with jsonl_path.open("w", encoding="utf-8") as handle:
        for index, message in enumerate(messages, start=1):
            text, digest = _norm_text(message["content"]), sha256_text(message["content"])
            obj = {"matrix_row_id": f"MMSG{index:06d}", "row_type": "message", "role": message["role"],
                   "chat_index": message["chat_index"], "prompt_id": message["prompt_id"], "response_id": message["response_id"],
                   "timestamp": message.get("timestamp"), "observation_text": text, "message_hash": digest,
                   "source_prompt_ids": [message["prompt_id"]], "source_response_ids": [message["response_id"]] if message["response_id"] else [],
                   "source_message_hashes": [digest]}
            handle.write(json.dumps(obj, ensure_ascii=False) + "\n")
    return str(csv_path), str(jsonl_path)


def build_session_header_artifacts(cell_dir: str | Path, header: Dict[str, Any]) -> Dict[str, str]:
    cell = Path(cell_dir)
    data, matrices, casefiles = cell / "data", cell / "data" / "matrices", cell / "casefiles"
    matrices.mkdir(parents=True, exist_ok=True); casefiles.mkdir(parents=True, exist_ok=True)
    obj = {"schema_version": header.get("schema_version"), "header_version": header.get("header_version"),
           "raw_text": header.get("raw_text"), "fields": header.get("fields", {}), "unknown_fields": header.get("unknown_fields", {}),
           "source": header.get("source", {}), "parser": {"name": "amcs_runtime", "version": __version__}}
    json_path = data / "session_header.json"; _write_json(json_path, obj)
    fields = obj["fields"]
    row = {"matrix_row_id": "MSH000001", "row_type": "session_header", "header_version": obj.get("header_version") or "",
           "domain": fields.get("domain", ""), "primary_question": fields.get("primary_question", ""), "scope": fields.get("scope", ""),
           "assumptions": "; ".join(fields.get("assumptions", []) or []), "constraints": fields.get("constraints", ""),
           "desired_output": fields.get("desired_output", ""), "stop_condition": fields.get("stop_condition", ""),
           "follow_ups": fields.get("follow_ups", ""), "sensitivity": fields.get("sensitivity", ""), "exclusions": fields.get("exclusions", ""),
           "source_prompt_ids": obj.get("source", {}).get("prompt_id", ""), "source_response_ids": obj.get("source", {}).get("response_id", ""),
           "source_message_hashes": obj.get("source", {}).get("message_hash", "")}
    csv_path = matrices / "session_header.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(row)); writer.writeheader(); writer.writerow(row)
    jsonl_path = matrices / "session_header.jsonl"
    jrow = dict(row)
    for key in ("source_prompt_ids", "source_response_ids", "source_message_hashes"):
        jrow[key] = [row[key]] if row[key] else []
    jsonl_path.write_text(json.dumps(jrow, ensure_ascii=False) + "\n", encoding="utf-8")
    casefile = casefiles / "CF_SESSION_HEADER.md"; source = obj.get("source", {})
    lines = ["# Case File: Session Header (CF_SESSION_HEADER)", "", "## What this is",
             "A structured FIRST-ORDER capture of the optional session header block.", "", "## Provenance",
             f"- prompt_id: {source.get('prompt_id', '')}", f"- response_id: {source.get('response_id', '')}",
             f"- message_hash: {source.get('message_hash', '')}", "", "## Header (verbatim)", "```",
             (obj.get("raw_text") or "").rstrip("\n"), "```", "", "## Parsed fields"]
    for key in HEADER_FIELD_ORDER:
        value = fields.get(key, ""); value = "; ".join(value or []) if key == "assumptions" else value
        lines.append(f"- {key}: {value}")
    casefile.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    return {"session_header_json": str(json_path.relative_to(cell)), "session_header_csv": str(csv_path.relative_to(cell)),
            "session_header_jsonl": str(jsonl_path.relative_to(cell)), "session_header_casefile": str(casefile.relative_to(cell))}


def build_case_files(cell_dir: str | Path, messages: List[Dict[str, Any]], scope: str, primary_source: str) -> str:
    cell = Path(cell_dir); path = cell / "casefiles" / "CF_MESSAGES.md"; path.parent.mkdir(parents=True, exist_ok=True)
    first, last = (messages[0]["prompt_id"] if messages else ""), (messages[-1]["prompt_id"] if messages else "")
    path.write_text(f"# Case File: Messages Matrix (CF_MESSAGES)\nScope: {scope}\nPrimary narrative source: {primary_source}\n\n"
                    f"## What this case file is\nCanonical narrative anchor for the FIRST-ORDER messages matrix.\n\n"
                    f"## Provenance\n- prompt_id range: {first} → {last}\n- total messages: {len(messages)}\n",
                    encoding="utf-8")
    return str(path)


def build_case_study_map(cell_dir: str | Path, messages: List[Dict[str, Any]], session_header: Optional[Dict[str, Any]] = None) -> str:
    cell = Path(cell_dir); nodes: List[Dict[str, Any]] = []; edges: List[Dict[str, Any]] = []
    nodes.append({"node_id": "NCF000001", "node_type": "case_file", "label": "CF_MESSAGES",
                  "source_prompt_ids": [messages[0]["prompt_id"]] if messages else [], "source_response_ids": [],
                  "source_message_hashes": [sha256_text(messages[0]["content"])] if messages else []})
    last_user = None; edge_counter = 0
    for index, message in enumerate(messages, start=1):
        node_id, digest = f"NMSG{index:06d}", sha256_text(message["content"])
        nodes.append({"node_id": node_id, "node_type": "claim", "label": f"{message['role']}@{message['prompt_id']}",
                      "source_prompt_ids": [message["prompt_id"]], "source_response_ids": [message["response_id"]] if message["response_id"] else [],
                      "source_message_hashes": [digest]})
        edge_counter += 1
        edges.append({"edge_id": f"E{edge_counter:06d}", "from_node_id": "NCF000001", "to_node_id": node_id,
                      "edge_type": "references", "edge_epistemic_class": "relational", "source_prompt_ids": [message["prompt_id"]],
                      "source_response_ids": [message["response_id"]] if message["response_id"] else [], "source_message_hashes": [digest]})
        if message["role"] == "user": last_user = node_id
        elif last_user:
            edge_counter += 1
            edges.append({"edge_id": f"E{edge_counter:06d}", "from_node_id": node_id, "to_node_id": last_user,
                          "edge_type": "responds_to", "edge_epistemic_class": "relational", "source_prompt_ids": [message["prompt_id"]],
                          "source_response_ids": [message["response_id"]] if message["response_id"] else [], "source_message_hashes": [digest]})
    if session_header and messages:
        source = session_header.get("source", {})
        nodes.append({"node_id": "NCF000002", "node_type": "case_file", "label": "CF_SESSION_HEADER",
                      "source_prompt_ids": [source.get("prompt_id")] if source.get("prompt_id") else [],
                      "source_response_ids": [source.get("response_id")] if source.get("response_id") else [],
                      "source_message_hashes": [source.get("message_hash")] if source.get("message_hash") else []})
        edge_counter += 1
        edges.append({"edge_id": f"E{edge_counter:06d}", "from_node_id": "NCF000002", "to_node_id": "NMSG000001",
                      "edge_type": "references", "edge_epistemic_class": "relational", "source_prompt_ids": [source.get("prompt_id")] if source.get("prompt_id") else [],
                      "source_response_ids": [source.get("response_id")] if source.get("response_id") else [],
                      "source_message_hashes": [source.get("message_hash")] if source.get("message_hash") else []})
    path = cell / "data" / "case_study_map.json"; _write_json(path, {"nodes": nodes, "edges": edges}); return str(path)


def write_cell_readme(cell_dir: str | Path, scope: str, has_session_header: bool) -> str:
    cell = Path(cell_dir); path = cell / "README.md"
    order = ["- `casefiles/CF_MESSAGES.md`", "- `data/prompt_log.json`", "- `data/matrices/messages.csv`", "- `data/case_study_map.json`"]
    if has_session_header: order.insert(0, "- `casefiles/CF_SESSION_HEADER.md`")
    path.write_text("# AMCS Memory Cell (INTERNAL)\n\n## Read order\n" + "\n".join(order) +
                    "\n\n## Authority rules\n- Narrative is canonical for meaning.\n- Matrices are FIRST-ORDER only.\n"
                    "- Graph edges are traversal aids and do not assert new facts.\n\nScope: " + scope + "\n", encoding="utf-8")
    return str(path)


_MANIFEST_EXCLUDES = {"manifests/file_hashes.sha256", "manifests/seal_receipt.json"}


def _iter_regular_files(root: Path) -> Iterable[Path]:
    for path in sorted(root.rglob("*")):
        if path.is_symlink(): raise AMCSSecurityError(f"symlink forbidden in cell: {path}")
        if path.is_file(): yield path


def build_file_hashes_manifest(cell_dir: str | Path) -> str:
    cell = Path(cell_dir); manifest = cell / "manifests" / "file_hashes.sha256"; manifest.parent.mkdir(parents=True, exist_ok=True)
    lines = []
    for path in _iter_regular_files(cell):
        rel = path.relative_to(cell).as_posix()
        if rel not in _MANIFEST_EXCLUDES: lines.append(f"{sha256_file(path)}  {rel}")
    manifest.write_text("\n".join(lines) + "\n", encoding="utf-8"); return str(manifest)


def build_seal_receipt(cell_dir: str | Path, genesis: str, scope: str, primary_source: str, case_id: str, cell_id: str,
                       session_meta: Optional[Dict[str, Any]]) -> str:
    cell = Path(cell_dir); manifest = cell / "manifests" / "file_hashes.sha256"
    receipt = {"genesis_prompt_verbatim": genesis, "runtime_version": __version__, "scope": scope,
               "run_mode_note": "INTERNAL profile; full crawl; no redactions", "primary_narrative_source": primary_source,
               "case_study_id": case_id, "cell_id": cell_id, "session_header": session_meta or {"present": False},
               "content_hash": sha256_file(manifest), "build_timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()}
    path = cell / "manifests" / "seal_receipt.json"; _write_json(path, receipt); return str(path)


def verify_cell_dir(cell_dir: str | Path) -> Tuple[bool, List[str]]:
    cell = Path(cell_dir); errors: List[str] = []; manifest = cell / "manifests" / "file_hashes.sha256"; receipt_path = cell / "manifests" / "seal_receipt.json"
    if not manifest.is_file(): return False, ["missing manifests/file_hashes.sha256"]
    if not receipt_path.is_file(): return False, ["missing manifests/seal_receipt.json"]
    listed: set[str] = set()
    for raw in manifest.read_text(encoding="utf-8").splitlines():
        if not raw.strip(): continue
        match = re.fullmatch(r"([a-f0-9]{64})  (.+)", raw)
        if not match: errors.append(f"bad hash line: {raw}"); continue
        expected, rel = match.groups(); pure = PurePosixPath(rel)
        if pure.is_absolute() or ".." in pure.parts: errors.append(f"unsafe manifest path: {rel}"); continue
        listed.add(rel); full = _resolved_child(cell, cell.joinpath(*pure.parts))
        if not full.is_file() or full.is_symlink(): errors.append(f"missing/non-regular manifest file: {rel}")
        elif sha256_file(full) != expected: errors.append(f"hash mismatch: {rel}")
    actual = {p.relative_to(cell).as_posix() for p in _iter_regular_files(cell) if p.relative_to(cell).as_posix() not in _MANIFEST_EXCLUDES}
    for rel in sorted(actual - listed): errors.append(f"unlisted file: {rel}")
    for rel in sorted(listed - actual): errors.append(f"manifest-only file: {rel}")
    for rel in ("data/prompt_log.json", "data/prompt_response_map.json", "data/matrices/messages.csv", "data/matrices/messages.jsonl",
                "data/case_study_map.json", "casefiles/CF_MESSAGES.md", "README.md"):
        if not (cell / rel).is_file(): errors.append(f"missing required artifact: {rel}")
    try:
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        if receipt.get("content_hash") != sha256_file(manifest): errors.append("seal receipt content_hash does not match manifest")
        if receipt.get("session_header", {}).get("present") is True:
            for rel in ("data/session_header.json", "data/matrices/session_header.csv", "data/matrices/session_header.jsonl", "casefiles/CF_SESSION_HEADER.md"):
                if not (cell / rel).is_file(): errors.append(f"missing session header artifact: {rel}")
    except (OSError, json.JSONDecodeError, TypeError) as exc: errors.append(f"invalid seal receipt: {type(exc).__name__}")
    try:
        pl = json.loads((cell / "data/prompt_log.json").read_text(encoding="utf-8")); prm = json.loads((cell / "data/prompt_response_map.json").read_text(encoding="utf-8"))
        assistants = sum(1 for entry in pl if entry.get("role") == "assistant")
        if assistants != len(prm.get("mappings", [])): errors.append(f"causality coverage mismatch: assistant_messages={assistants} mappings={len(prm.get('mappings', []))}")
    except (OSError, json.JSONDecodeError, TypeError) as exc: errors.append(f"causality verification error: {type(exc).__name__}")
    return not errors, errors


def _validate_tar_member(member: tarfile.TarInfo) -> PurePosixPath:
    pure = PurePosixPath(member.name)
    if pure.is_absolute() or not pure.parts or ".." in pure.parts: raise AMCSSecurityError(f"unsafe archive path: {member.name}")
    if member.issym() or member.islnk() or member.isdev() or member.isfifo(): raise AMCSSecurityError(f"archive link/special file forbidden: {member.name}")
    if not (member.isdir() or member.isfile()): raise AMCSSecurityError(f"unsupported archive member type: {member.name}")
    return pure


def safe_extract_tar(archive: str | Path, destination: str | Path, *, max_members: int = DEFAULT_MAX_ARCHIVE_MEMBERS,
                     max_expanded_bytes: int = DEFAULT_MAX_EXPANDED_BYTES) -> None:
    if max_members < 1 or max_expanded_bytes < 1: raise ValueError("archive limits must be positive")
    dest = Path(destination).resolve(); dest.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive, "r:*") as tar:
        members = tar.getmembers()
        if len(members) > max_members: raise AMCSSecurityError(f"archive member limit exceeded: {len(members)} > {max_members}")
        expanded = 0; checked: List[Tuple[tarfile.TarInfo, PurePosixPath]] = []
        for member in members:
            pure = _validate_tar_member(member)
            if member.isfile():
                expanded += member.size
                if expanded > max_expanded_bytes: raise AMCSSecurityError("archive expanded-size limit exceeded")
            checked.append((member, pure))
        for member, pure in checked:
            target = _resolved_child(dest, dest.joinpath(*pure.parts))
            if member.isdir(): target.mkdir(parents=True, exist_ok=True); continue
            target.parent.mkdir(parents=True, exist_ok=True); source = tar.extractfile(member)
            if source is None: raise AMCSSecurityError(f"unable to read archive member: {member.name}")
            with source, target.open("wb") as output: shutil.copyfileobj(source, output, length=1024 * 1024)


def _single_root(extracted: Path) -> Path:
    roots = list(extracted.iterdir())
    if len(roots) != 1 or not roots[0].is_dir() or roots[0].is_symlink(): raise AMCSValidationError("cell archive must contain exactly one root directory")
    return roots[0]


def verify_archive(archive: str | Path, *, max_members: int = DEFAULT_MAX_ARCHIVE_MEMBERS,
                   max_expanded_bytes: int = DEFAULT_MAX_EXPANDED_BYTES) -> Tuple[bool, List[str]]:
    try:
        with tempfile.TemporaryDirectory(prefix="amcs_verify_") as tmp:
            root = Path(tmp); safe_extract_tar(archive, root, max_members=max_members, max_expanded_bytes=max_expanded_bytes)
            return verify_cell_dir(_single_root(root))
    except (AMCSError, tarfile.TarError, OSError, ValueError) as exc: return False, [str(exc)]


def _create_tar_from_directory(source: Path, archive: Path, arcname: str) -> None:
    tmp = archive.with_name(archive.name + ".tmp"); tmp.unlink(missing_ok=True)
    try:
        with tarfile.open(tmp, "w:gz") as tar: tar.add(source, arcname=arcname, recursive=True)
        os.replace(tmp, archive)
    finally: tmp.unlink(missing_ok=True)


def seal(args: argparse.Namespace) -> str:
    cell_id = _validate_identifier(args.cell_name, "cell-name"); out_root = Path(args.out_dir).resolve(); out_root.mkdir(parents=True, exist_ok=True)
    final = _safe_output_path(out_root, f"{cell_id}.tar.gz")
    messages = load_chat(args.input); messages, _ = deterministic_ids(messages)
    header = extract_session_header(messages) if getattr(args, "parse_session_header", True) else None
    scope = args.scope or "entire_chat"; genesis = args.genesis_prompt or AMCS_INIT_SEED_DEFAULT; case_id = sha256_text(genesis + "|" + scope)[:16]
    with tempfile.TemporaryDirectory(prefix=f".{cell_id}.", dir=out_root) as tmp:
        cell = Path(tmp) / cell_id; cell.mkdir(); copy_evidence(args.odt, messages, args.attachments_root, cell / "evidence")
        _write_json(cell / "data" / "prompt_log.json", build_prompt_log(messages, scope)); _write_json(cell / "data" / "prompt_response_map.json", build_prompt_response_map(messages))
        build_messages_matrix(messages, cell / "data" / "matrices"); session_meta: Dict[str, Any] = {"present": False}
        if header:
            paths = build_session_header_artifacts(cell, header); session_meta = {"present": True, "header_version": header.get("header_version"),
                    "source": header.get("source"), "artifact_paths": paths, "parser_version": __version__}
        build_case_files(cell, messages, scope, args.primary_narrative_source); build_case_study_map(cell, messages, session_header=header); write_cell_readme(cell, scope, bool(header))
        build_file_hashes_manifest(cell); build_seal_receipt(cell, genesis, scope, args.primary_narrative_source, case_id, cell_id, session_meta)
        ok, errors = verify_cell_dir(cell)
        if not ok: raise AMCSValidationError("seal verification failed: " + "; ".join(errors))
        _create_tar_from_directory(cell, final, cell_id)
    return str(final)


def verify(args: argparse.Namespace) -> int:
    ok, errors = verify_archive(args.cell, max_members=args.max_archive_members, max_expanded_bytes=args.max_expanded_bytes)
    if ok: print("PASS"); return 0
    print("FAIL")
    for error in errors: print("-", error)
    return 1


def assemble_supercell(args: argparse.Namespace) -> str:
    name = _validate_identifier(args.supercell_name, "supercell-name"); out_root = Path(args.out_dir).resolve(); out_root.mkdir(parents=True, exist_ok=True)
    final = _safe_output_path(out_root, f"{name}.tar.gz")
    for cell_path in args.cells:
        ok, errors = verify_archive(cell_path, max_members=args.max_archive_members, max_expanded_bytes=args.max_expanded_bytes)
        if not ok: raise AMCSValidationError(f"child cell failed verification: {cell_path}: {'; '.join(errors)}")
    with tempfile.TemporaryDirectory(prefix=f".{name}.", dir=out_root) as tmp:
        root = Path(tmp) / name; cells = root / "cells"; cells.mkdir(parents=True); included = []
        for index, cell_path in enumerate(args.cells, start=1):
            source = Path(cell_path).resolve(strict=True); destination = cells / f"cell_{index:03d}.tar.gz"; shutil.copy2(source, destination)
            included.append({"path": destination.relative_to(root).as_posix(), "sha256": sha256_file(destination)})
        _write_json(root / "supercell_manifest.json", {"supercell_id": f"SC_{sha256_text(name)[:12]}",
                    "assembly_timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(), "assembly_reason": args.reason or "task-scoped assembly",
                    "included_cells": included, "assembly_scope": args.scope, "assembly_mode": args.mode, "notes": args.notes or "", "runtime_version": __version__})
        _create_tar_from_directory(root, final, name)
    return str(final)


def main() -> int:
    parser = argparse.ArgumentParser(); sub = parser.add_subparsers(dest="cmd", required=True)
    ps = sub.add_parser("seal"); ps.add_argument("--input", required=True); ps.add_argument("--out-dir", required=True); ps.add_argument("--cell-name", required=True)
    ps.add_argument("--scope", default="entire_chat"); ps.add_argument("--primary-narrative-source", default="chat", choices=["odt", "chat", "both"]); ps.add_argument("--odt", default=None)
    ps.add_argument("--attachments-root", default=None); ps.add_argument("--genesis-prompt", default=None); group = ps.add_mutually_exclusive_group()
    group.add_argument("--parse-session-header", dest="parse_session_header", action="store_true", default=True); group.add_argument("--no-parse-session-header", dest="parse_session_header", action="store_false")
    pv = sub.add_parser("verify"); pv.add_argument("--cell", required=True); pv.add_argument("--max-archive-members", type=int, default=DEFAULT_MAX_ARCHIVE_MEMBERS); pv.add_argument("--max-expanded-bytes", type=int, default=DEFAULT_MAX_EXPANDED_BYTES)
    pa = sub.add_parser("assemble-supercell"); pa.add_argument("--cells", nargs="+", required=True); pa.add_argument("--out-dir", required=True); pa.add_argument("--supercell-name", required=True); pa.add_argument("--scope", required=True)
    pa.add_argument("--mode", default="research", choices=["analysis", "research", "consolidation", "planning"]); pa.add_argument("--reason", default=None); pa.add_argument("--notes", default=None)
    pa.add_argument("--max-archive-members", type=int, default=DEFAULT_MAX_ARCHIVE_MEMBERS); pa.add_argument("--max-expanded-bytes", type=int, default=DEFAULT_MAX_EXPANDED_BYTES)
    args = parser.parse_args()
    try:
        if args.cmd == "seal": print(seal(args)); return 0
        if args.cmd == "verify": return verify(args)
        if args.cmd == "assemble-supercell": print(assemble_supercell(args)); return 0
        return 2
    except (AMCSError, OSError, ValueError, tarfile.TarError) as exc:
        print(f"ERROR: {exc}"); return 2


if __name__ == "__main__":
    raise SystemExit(main())
