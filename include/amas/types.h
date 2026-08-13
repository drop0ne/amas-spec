#ifndef AMAS_TYPES_H
#define AMAS_TYPES_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Canonical JSON v1 exact-integer wire ceiling. */
#define AMAS_JSON_SAFE_UINT64 UINT64_C(9007199254740991)
#define AMAS_JSON_SAFE_INT64  INT64_C(9007199254740991)

/* Fixed-width internal representations. Wire encoding remains JSON/RFC3339. */
typedef uint8_t  amas_authority_tier_t;
typedef uint8_t  amas_semantic_role_t;
typedef uint8_t  amas_side_effect_t;
typedef uint64_t amas_counter_t;
typedef int64_t  amas_signed_integer_t;

typedef struct amas_sha256 {
    uint8_t bytes[32];
} amas_sha256_t;

typedef struct amas_utf8_view {
    const char *data;
    uint64_t length;
} amas_utf8_view_t;

typedef struct amas_timestamp_view {
    /* RFC3339 / JSON date-time text; no platform-dependent time_t on wire. */
    const char *data;
    uint64_t length;
} amas_timestamp_view_t;

enum {
    AMAS_TIER_CANONICAL = 0u,
    AMAS_TIER_OPERATOR  = 1u,
    AMAS_TIER_SESSION   = 2u,
    AMAS_TIER_INFERRED  = 3u
};

enum {
    AMAS_ROLE_DIRECTIVE   = 0u,
    AMAS_ROLE_EVIDENCE    = 1u,
    AMAS_ROLE_OBSERVATION = 2u,
    AMAS_ROLE_INFERENCE   = 3u
};

enum {
    AMAS_EFFECT_OBSERVE          = 0u,
    AMAS_EFFECT_SIMULATE         = 1u,
    AMAS_EFFECT_REVERSIBLE_WRITE = 2u,
    AMAS_EFFECT_PERSISTENT_WRITE = 3u,
    AMAS_EFFECT_PRIVILEGED_CHANGE = 4u
};

#if defined(__cplusplus)
static_assert(sizeof(uint8_t) == 1, "AMAS requires an 8-bit uint8_t");
static_assert(sizeof(uint64_t) == 8, "AMAS requires a 64-bit uint64_t");
static_assert(sizeof(int64_t) == 8, "AMAS requires a 64-bit int64_t");
static_assert(sizeof(amas_sha256_t) == 32, "AMAS SHA-256 representation must be 32 bytes");
#else
_Static_assert(sizeof(uint8_t) == 1, "AMAS requires an 8-bit uint8_t");
_Static_assert(sizeof(uint64_t) == 8, "AMAS requires a 64-bit uint64_t");
_Static_assert(sizeof(int64_t) == 8, "AMAS requires a 64-bit int64_t");
_Static_assert(sizeof(amas_sha256_t) == 32, "AMAS SHA-256 representation must be 32 bytes");
#endif

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* AMAS_TYPES_H */
