# AMAS Portable Type Profile v1

**Status:** Normative portability profile for machine-readable AMAS/AAB/AMCS fields.  
**Goal:** every normative wire value must map without semantic ambiguity to fixed-width C and C++ types.

## 1. General rule

The JSON wire format is language-neutral. Implementations MUST NOT depend on Python-only integer, tuple, set, object, or exception semantics.

Security-sensitive numeric fields use fixed-width C/C++ representable domains. Where Canonical JSON v1 imposes a narrower interoperability range, the narrower range controls.

## 2. Primitive mappings

| AMAS type | JSON wire form | C representation | C++ representation | Normative range / rule |
|---|---|---|---|---|
| `amas_bool` | boolean | `bool` from `<stdbool.h>` | `bool` | `false` or `true`; never interchangeable with integer 0/1 for identity/equality |
| `amas_u8` | integer | `uint8_t` | `std::uint8_t` | `0..255` |
| `amas_u32` | integer | `uint32_t` | `std::uint32_t` | `0..4294967295` |
| `amas_i64_safe` | integer | `int64_t` | `std::int64_t` | `-9007199254740991..9007199254740991` |
| `amas_u64_safe` | integer | `uint64_t` | `std::uint64_t` | `0..9007199254740991` |
| `amas_f64_unit` | number | `double` | `double` | finite `0.0..1.0`; prohibited in Canonical JSON v1 security objects |
| `amas_utf8` | string | `char *` + explicit byte length | `std::string` | valid UTF-8 encoding of Unicode scalar values; no lone surrogates |
| `amas_hash256` | 64-char lowercase hex string | `uint8_t[32]` internally | `std::array<std::uint8_t,32>` internally | JSON form is exactly 64 lowercase hexadecimal characters |
| `amas_timestamp` | string | parsed explicit timestamp structure | parsed explicit timestamp structure | timezone-aware RFC 3339 / JSON Schema `date-time`; do not serialize native `time_t` |

The names above describe semantic domains. They do not require an implementation to expose typedefs with those exact names.

## 3. Field guidance

- authority tiers and compact enumerated states SHOULD use an `amas_u8` internal representation;
- sequences, generations, counts, budgets, byte counts, and durations MUST fit `amas_u64_safe` when represented as Canonical JSON security integers;
- signed security-domain integers MUST fit `amas_i64_safe`;
- hashes/signatures remain byte arrays internally and lowercase hexadecimal strings on the JSON wire unless a specific protocol explicitly defines another encoding;
- IDs, principals, objective IDs, target IDs, destination IDs, credential references, policy IDs, lease IDs, request IDs, nonces, and scope-path elements are `amas_utf8` strings, not native pointers or integer handles on the wire.

## 4. Collections and nullable values

JSON arrays map to:

- C: an element pointer plus an explicit `size_t` length owned according to the embedding API;
- C++: `std::vector<T>` or another contiguous/ordered sequence with equivalent semantics.

JSON objects map to explicitly declared structs/classes for normative protocol objects. Generic hash maps MAY be used during parsing, but unknown members MUST be rejected wherever the schema has `additionalProperties: false`.

Nullable fields map to tagged presence, not magic sentinel values:

- C: `{ bool has_value; T value; }` or equivalent;
- C++: `std::optional<T>` or equivalent.

## 5. Enums

Normative JSON enums may remain human-readable strings on the wire. A C/C++ implementation SHOULD map each recognized value to a closed fixed-width enum representation, normally backed by `uint8_t` when the value count permits.

Unknown enum strings MUST fail closed for authority/security decisions.

## 6. Numeric portability rules

Implementations MUST NOT place the following directly into a Canonical JSON v1 security object:

- native `long` or `unsigned long` values whose width is platform-dependent;
- `size_t`, pointer values, or memory addresses;
- floating-point values;
- arbitrary-precision integers outside the AMAS safe ranges;
- NaN or infinities.

Values originating in those types MUST be range-checked and normalized into the applicable AMAS fixed-width semantic domain before hashing, signing, authorization, or receipt generation.

The `±(2^53-1)` Canonical JSON integer boundary is intentionally narrower than `int64_t`/`uint64_t`. This preserves exact interoperability with common JSON runtimes while remaining directly representable in standard C99/C11 and modern C++ fixed-width integer types.

## 7. Equality

Protocol equality is typed equality.

- `true` is not integer `1`;
- `false` is not integer `0`;
- string `"1"` is not integer `1`;
- a 64-character hash string is validated as `amas_hash256`, not treated as an arbitrary unvalidated string when a hash is required.

This rule is security-relevant for capability allowlists, canonical hashing, and authority comparisons.

## 8. Conformance

A non-Python implementation may claim portable-type conformance only when it:

1. rejects out-of-range values before authority evaluation or cryptographic binding;
2. distinguishes booleans from integers;
3. rejects unknown fields and enum values where the normative schema is closed;
4. reproduces Canonical JSON v1 bytes and hashes for the repository conformance vectors;
5. does not rely on implementation-defined C/C++ integer widths for wire semantics.
