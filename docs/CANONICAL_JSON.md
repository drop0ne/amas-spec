# AMAS/AAB Canonical JSON v1

**Status:** Normative reference encoding for security-object hashing/signing in this repository.  
**Reference:** `reference/canonical_json.py`  
**Portable types:** `docs/PORTABLE_TYPES.md`

## Purpose

Cryptographic identities are meaningful only if independent implementations serialize the same security object to the same bytes. Canonical JSON v1 therefore defines a deliberately narrow, deterministic JSON subset rather than relying on a runtime's default serializer.

## Allowed value model

Security objects hashed or authenticated under Canonical JSON v1 may contain only:

- objects with **string keys only**;
- arrays, preserving order;
- strings containing Unicode scalar values (no lone surrogates);
- integers in the inclusive range `[-9007199254740991, 9007199254740991]` (`±(2^53-1)`);
- `true`, `false`, and `null`.

Forbidden values include floating-point numbers (including finite floats), `NaN`, infinities, integers outside the interoperable safe range, surrogate code points, non-string object keys, sets, tuples, bytes, or custom language objects.

## C/C++ portability

Canonical JSON wire values MUST map to the fixed-width domains in `docs/PORTABLE_TYPES.md`.

In particular:

- Canonical JSON integers fit `int64_t`; nonnegative counters/limits fit `uint64_t` while remaining restricted to the narrower `2^53-1` interoperability ceiling;
- compact protocol enums and authority tiers SHOULD use fixed-width byte-sized internal representations such as `uint8_t`;
- booleans are typed booleans and MUST NOT compare equal to integer `0` or `1` for protocol equality;
- hashes may be stored internally as 32-byte arrays and are serialized as 64 lowercase hexadecimal characters where the enclosing schema specifies a SHA-256 value;
- native `long`, `size_t`, pointer values, memory addresses, platform-width integers, or implementation-specific objects MUST NOT define wire semantics.

A C or C++ implementation does not need to reproduce Python container types. It needs to reproduce the same typed JSON value model and the exact bytes defined below.

## Property ordering

Object keys are sorted lexicographically by their **UTF-16 code units**, compared as unsigned 16-bit values. This rule is explicit because Unicode scalar/code-point ordering differs from UTF-16 ordering for some supplementary-plane characters.

Array order is never changed.

## String serialization

Strings are emitted as JSON strings using the following deterministic rules:

- `"` becomes `\"`;
- `\` becomes `\\`;
- U+0008, U+0009, U+000A, U+000C, and U+000D use `\b`, `\t`, `\n`, `\f`, and `\r`;
- other U+0000–U+001F characters use lowercase `\u00xx` escapes;
- all other Unicode scalar values are emitted directly and encoded as UTF-8;
- lone surrogate code points are invalid.

No insignificant whitespace is emitted.

## Integers only

The authority/security objects in this repository do not require binary floating-point values. Excluding floats avoids cross-runtime formatting and rounding ambiguity. The safe integer bound avoids silent precision loss in common JSON runtimes whose exact integer interoperability is limited by IEEE-754 binary64.

The `±(2^53-1)` range is intentionally a subset of standard fixed-width C/C++ `int64_t`/`uint64_t` capacity. This gives C/C++ implementations deterministic native storage while preserving exact JSON interoperability with runtimes that use binary64 numbers.

If an adapter needs a fractional domain value, it MUST normalize it before the value enters an AAB security object, for example as a scaled integer or an adapter-defined canonical decimal string.

## Hashing

Unless a more specific normative document states otherwise:

```text
SHA-256 = sha256(canonical_json_v1_utf8_bytes(object))
```

The hardened reference applies this encoding to authority policies and requests, signed leases, capability-contract identities, prepared-action bindings, exact parent-policy delegation hashes, AAB decision receipts, and durable broker hash/MAC inputs that use the shared broker canonicalization path.

AMCS file/archive hashing remains byte-oriented under the AMCS specification; AMCS JSON structures use their separately documented binding rules.

## Compatibility

Changing any rule in this document changes cryptographic identity. A future Canonical JSON v2 therefore requires explicit versioning/migration rather than silently reinterpreting existing signatures, hashes, contract IDs, receipts, or parent-policy bindings.
