#!/usr/bin/env python3
"""Tamper-evident hash chain for AMAS AAB decision receipts."""
from __future__ import annotations

import hashlib
import json
from typing import Any, Iterable

GENESIS = "0" * 64


def canonical_hash(obj: Any) -> str:
    raw = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def append_receipt(receipt: dict[str, Any], previous_hash: str = GENESIS, sequence: int = 0) -> dict[str, Any]:
    if not isinstance(previous_hash, str) or len(previous_hash) != 64:
        raise ValueError("previous_hash must be a 64-character SHA-256 hex string")
    if sequence < 0:
        raise ValueError("sequence must be non-negative")
    payload = dict(receipt)
    payload["sequence"] = sequence
    payload["previous_receipt_hash"] = previous_hash
    payload["receipt_hash"] = canonical_hash({k: v for k, v in payload.items() if k != "receipt_hash"})
    return payload


def verify_chain(receipts: Iterable[dict[str, Any]]) -> dict[str, Any]:
    previous = GENESIS
    expected_sequence = 0
    count = 0
    for receipt in receipts:
        count += 1
        if receipt.get("sequence") != expected_sequence:
            return {"valid": False, "reason": "sequence_mismatch", "index": expected_sequence}
        if receipt.get("previous_receipt_hash") != previous:
            return {"valid": False, "reason": "previous_hash_mismatch", "index": expected_sequence}
        claimed = receipt.get("receipt_hash")
        computed = canonical_hash({k: v for k, v in receipt.items() if k != "receipt_hash"})
        if claimed != computed:
            return {"valid": False, "reason": "receipt_hash_mismatch", "index": expected_sequence}
        previous = claimed
        expected_sequence += 1
    return {"valid": True, "reason": "verified", "count": count, "chain_tip": previous}
