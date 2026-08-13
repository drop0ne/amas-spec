#!/usr/bin/env python3
"""Tamper-evident SHA-256 hash chain for AMAS AAB decision receipts."""
from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable

GENESIS = "0" * 64


def canonical_hash(obj: Any) -> str:
    raw = json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def re_full_sha256(value: str) -> bool:
    if len(value) != 64:
        return False
    try:
        return value == value.lower() and int(value, 16) >= 0
    except ValueError:
        return False


def append_receipt(receipt: dict[str, Any], previous_hash: str = GENESIS, sequence: int = 0) -> dict[str, Any]:
    if not isinstance(previous_hash, str) or not re_full_sha256(previous_hash):
        raise ValueError("previous_hash must be a lowercase 64-character SHA-256 hex string")
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 0:
        raise ValueError("sequence must be a non-negative integer")
    if not isinstance(receipt, dict):
        raise ValueError("receipt must be an object")
    payload = dict(receipt)
    payload["sequence"] = sequence
    payload["previous_receipt_hash"] = previous_hash
    payload["receipt_hash"] = canonical_hash({k: v for k, v in payload.items() if k != "receipt_hash"})
    return payload


def verify_chain(receipts: Iterable[dict[str, Any]]) -> dict[str, Any]:
    previous = GENESIS
    expected_sequence = 0
    count = 0
    try:
        iterator = iter(receipts)
    except TypeError:
        return {"valid": False, "reason": "receipts_not_iterable", "index": 0}

    try:
        for receipt in iterator:
            count += 1
            if not isinstance(receipt, dict):
                return {"valid": False, "reason": "receipt_not_object", "index": expected_sequence}
            if receipt.get("sequence") != expected_sequence:
                return {"valid": False, "reason": "sequence_mismatch", "index": expected_sequence}
            if receipt.get("previous_receipt_hash") != previous:
                return {"valid": False, "reason": "previous_hash_mismatch", "index": expected_sequence}
            claimed = receipt.get("receipt_hash")
            if not isinstance(claimed, str) or not re_full_sha256(claimed):
                return {"valid": False, "reason": "invalid_receipt_hash", "index": expected_sequence}
            computed = canonical_hash({k: v for k, v in receipt.items() if k != "receipt_hash"})
            if claimed != computed:
                return {"valid": False, "reason": "receipt_hash_mismatch", "index": expected_sequence}
            previous = claimed
            expected_sequence += 1
    except (TypeError, ValueError, RecursionError):
        return {"valid": False, "reason": "receipt_not_canonical_json", "index": expected_sequence}
    return {"valid": True, "reason": "verified", "count": count, "chain_tip": previous}
