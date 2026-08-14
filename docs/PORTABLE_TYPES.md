# AMAS Portable Type Profile v1

**Status:** Normative portability profile for machine-readable AMAS/AAB/AMCS fields.  
**Goal:** every normative wire value maps without semantic ambiguity to fixed-width C and C++ types.

The corresponding portable C header is `include/amas/types.h` and is compiled as both C11 and C++17 in CI.

## 1. General rule

The JSON wire format is language-neutral. Implementations MUST NOT depend on Python-only integer, tuple, set, object, or exception semantics.

Security-sensitive numeric fields use fixed-width C/C++ representable domains. Where Canonical JSON v1 imposes a narrower interoperability range, the narrower range controls.

## 2. Primitive mappings

| AMAS type | JSON wire form | C representation | C++ representation | Normative range / rule |
|---|---|---|---|---|
| `amas_bool` | boolean | `bool` | `bool` | `false` or `true`; never interchangeable with integer 0/1 |
| `amas_u8` | integer | `uint8_t` | `std::uint8_t` | `0..255` |
| `amas_u32` | integer | `uint32_t` | `std::uint32_t` | `0..4294967295` |
| `amas_i64_safe` | integer | `int64_t` | `std::int64_t` | `-9007199254740991..9007199254740991` |
| `amas_u64_safe` | integer | `uint64_t` | `std::uint64_t` | `0..9007199254740991` |
| `amas_f64_unit` | number | `double` | `double` | finite `0.0..1.0`; prohibited in Canonical JSON v1 security objects |
| `amas_utf8` | string | pointer + explicit `uint64_t` byte length | string/view + explicit checked length | valid UTF-8 scalar values; no lone surrogates |
| `amas_hash256` | lowercase hex string | `uint8_t[32]` internally | `std::array<std::uint8_t,32>` internally | JSON form exactly 64 lowercase hex characters |
| `amas_timestamp` | string | explicit RFC3339 text view / parsed struct | explicit RFC3339 text view / parsed type | timezone-aware; never serialize native `time_t` |

`include/amas/types.h` uses `uint64_t` lengths for protocol-facing UTF-8/timestamp views. An embedding API MAY use `size_t` internally after range checking, but `size_t` is never a normative wire type because its width is platform-dependent.

## 3. Field guidance

- authority tiers and compact enumerated states SHOULD use `uint8_t` internally;
- sequences, generations, counts, budgets, byte counts, and durations MUST fit `amas_u64_safe` on the Canonical JSON wire;
- signed security integers MUST fit `amas_i64_safe`;
- hashes/signatures remain fixed byte arrays internally and lowercase hexadecimal strings on the JSON wire unless another encoding is explicitly versioned;
- IDs, principals, objectives, targets, destinations, credential references, policy/lease/request IDs, nonces, and scope-path elements are UTF-8 strings, never pointer values or integer handles on the wire.

## 4. Collections and nullable values

JSON arrays are ordered. A C protocol-facing view SHOULD use an element pointer plus explicit `uint64_t` element count; a C++ implementation may use `std::vector<T>` or an equivalent ordered container after bounds checking.

JSON objects map to explicitly declared structs/classes for normative protocol objects. Generic maps MAY be used while parsing, but unknown members MUST be rejected where the normative schema has `additionalProperties: false`.

Nullable values use tagged presence, not magic sentinels:

- C: `{ bool has_value; T value; }` or equivalent;
- C++: `std::optional<T>` or equivalent.

## 5. Enums

Normative JSON enums remain human-readable strings on the wire unless a specific versioned binary representation is defined. A C/C++ implementation SHOULD map recognized values to closed fixed-width internal codes, normally `uint8_t` when the value count permits.

Unknown enum strings MUST fail closed for authority/security decisions.

## 6. Numeric portability rules

Implementations MUST NOT place these directly into a Canonical JSON v1 security object:

- native `long` / `unsigned long` values without explicit range normalization;
- `size_t`, pointer values, or memory addresses;
- floating-point values;
- arbitrary-precision integers outside AMAS safe ranges;
- NaN or infinities.

Values originating in those domains MUST be checked and normalized into the applicable AMAS fixed-width semantic domain before hashing, signing, authorization, or receipt generation.

The `±(2^53-1)` Canonical JSON integer boundary is intentionally narrower than the `int64_t`/`uint64_t` storage range. This preserves exact interoperability with common JSON runtimes while remaining directly representable in C99/C11 and modern C++ fixed-width integer types.

## 7. Equality

Protocol equality is typed equality:

- `true` is not integer `1`;
- `false` is not integer `0`;
- string `"1"` is not integer `1`;
- a required hash is validated as `amas_hash256`, not accepted as an arbitrary string.

This is security-relevant for capability allowlists, canonical hashing, and authority comparisons.

## 8. Conformance

A non-Python implementation may claim portable-type conformance only when it:

1. rejects out-of-range values before authority evaluation or cryptographic binding;
2. distinguishes booleans from integers;
3. rejects unknown fields/enums where the normative schema is closed;
4. reproduces Canonical JSON v1 bytes and hashes for repository conformance vectors;
5. does not depend on implementation-defined C/C++ widths for wire semantics;
6. passes equivalent fixed-width/static-assert checks to `include/amas/types.h`.
