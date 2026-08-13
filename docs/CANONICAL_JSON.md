# AMAS/AAB Canonical JSON v1

**Status:** Normative reference encoding for security-object hashing/signing in this repository.  
**Reference:** `reference/canonical_json.py`

## Purpose

Cryptographic hashes are meaningful only if every implementation serializes the same logical security object to the same bytes.

Ordinary JSON serialization options are not sufficient as a cross-runtime security contract. In particular, floating-point rendering, non-finite values, Unicode edge cases, non-string object keys, and implementation-specific extensions can produce different bytes or different acceptance behavior.

Canonical JSON v1 therefore deliberately narrows the value domain used by AMAS/AAB security hashes.

## Allowed value model

Security objects hashed or authenticated under Canonical JSON v1 may contain only:

- JSON objects with **string keys only**;
- arrays, preserving array order;
- strings that encode as valid UTF-8 Unicode scalar sequences;
- integers;
- `true` / `false`;
- `null`.

The following are forbidden:

- floating-point values, even finite ones;
- `NaN`, `Infinity`, `-Infinity`;
- surrogate code points;
- non-string object keys;
- sets, tuples, byte strings, custom objects, or other language-specific values.

## Serialization

Canonical bytes are produced as follows:

1. recursively validate the allowed value model;
2. sort object keys by the runtime's Unicode-string ordering used by the reference implementation;
3. preserve array order;
4. emit UTF-8 directly rather than ASCII-only `\u` escaping;
5. emit no insignificant whitespace;
6. use ordinary JSON literals for integers, booleans, strings, arrays, objects, and null.

The Python reference is equivalent to the validated subset of:

```python
json.dumps(
    value,
    sort_keys=True,
    separators=(",", ":"),
    ensure_ascii=False,
    allow_nan=False,
).encode("utf-8", errors="strict")
```

The validation step is mandatory; the serializer call alone is not the complete contract.

## Why integers only

The current security objects do not require floating-point authority values. Cross-language floating-point canonicalization adds complexity and unnecessary ambiguity.

If an adapter needs a fractional domain value, it should define a stable representation before the value enters the AAB security object—for example:

- scaled integer units; or
- a validated canonical decimal string under an adapter-specific capability contract.

A deployment must not silently hash native binary floating-point values and call that equivalent to Canonical JSON v1.

## Hashing

Unless a more specific normative document says otherwise:

```text
SHA-256 = sha256(canonical_json_v1_bytes(object))
```

This encoding is used by the hardened reference for objects such as:

- authority policies and requests;
- authority leases;
- capability-contract identities;
- prepared-action bindings;
- delegation parent-policy hashes;
- AAB decision receipts;
- durable state/checkpoint MAC/hash inputs through the broker canonicalization path.

AMCS has separate file/archive hashing rules; JSON objects that use the shared canonical helper follow this encoding where stated.

## Compatibility

Changing the canonical encoding changes cryptographic identity. A future Canonical JSON v2 would therefore require explicit versioning/migration rather than silently reinterpreting existing hashes, signatures, contract IDs, receipts, or parent-policy bindings.
