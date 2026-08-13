# AMAS Runtime Binding Contract

**Status:** Draft RC3  
**Purpose:** runtime mechanics that implement AMAS governance without changing AMAS Core doctrine.

## 1. Scope

AMAS Core defines authority, semantic role, canonicality, and conflict/mutation boundaries. Runtime Binding defines activation, validation, append, repair, export, state transitions, and the seam to AAB for external side effects.

## 2. Core/runtime separation

AMAS Core decides what counts as authoritative. Runtime Binding defines how those requirements are represented and verified at runtime. AMCS is one memory persistence reference. AAB separately governs external action authority.

## 3. Ingestion and semantic-role binding

Runtime ingestion MUST preserve enough trusted metadata to assign both:

- `authority_tier`; and
- `semantic_role` (`DIRECTIVE`, `EVIDENCE`, `OBSERVATION`, `INFERENCE`).

Imperative wording MUST NOT elevate `EVIDENCE`, `OBSERVATION`, or `INFERENCE` into a directive.

Where one message/document contains semantically distinct directives and quoted/evidentiary material, implementations SHOULD segment those units rather than let message boundaries silently transfer directive authority.

A non-directive → directive transition MUST create a new auditable object issued by a principal already authorized to create that directive.

## 4. Activation contract

No authoritative mutation may occur without validated activation. A valid activation contract MUST expose at least:

- canonical root identifier/hash;
- root-uniqueness assertion;
- writable-ledger identifier/path;
- conformance profile;
- append/repair flags;
- activation timestamp;
- activation receipt hash.

If activation cannot be verified, the runtime remains non-mutating.

## 5. Preflight

Blocking checks SHOULD include canonical-root uniqueness, writable-ledger uniqueness, chain-tip integrity, schema compatibility, provenance/semantic-role validity, and manifest/hash consistency.

Derived-view synchronization and quarantine candidates may be advisory, but invalid/unprovenanced memory may not activate as authoritative state.

## 6. Deterministic conflict handling

Runtime conflict arbitration MUST implement the ordering in `SPEC.md`:

1. directive-role admissibility when behavior is at issue;
2. tier precedence;
3. explicit supersession;
4. explicit scope specificity;
5. recency;
6. unresolved → halt/escalate.

A runtime MUST NOT add an undocumented probabilistic or model-selected tie-breaker.

## 7. Append

Required sequence:

`stage → validate → hash → commit → regenerate derived views → emit receipt`

Append MUST preserve provenance/lineage and MUST NOT silently change semantic role or authority tier.

## 8. Repair

Repair is privileged. Allowed classes may include wrapper regeneration, derived-ledger rebuild, provenance-preserving chain correction, and migration.

Silent repair and silent canonical replacement are forbidden. Every authoritative repair requires a receipt.

## 9. Export proof bundle

Authoritative export MUST satisfy the declared conformance profile. A proof bundle SHOULD expose:

- conformance profile;
- canonical/state root hash;
- ledger/content digest;
- export timestamp;
- export receipt hash;
- operator-visible state hash;
- applicable action-decision chain tip where AAB is active.

## 10. Runtime states

Recommended states:

- `READ_ONLY_HYDRATE`
- `VALIDATING`
- `BIND_READY`
- `APPEND_READY`
- `REPAIR_READY`
- `EXPORT_READY`
- `CLOSED_FINALIZED`
- `BLOCKED`

`CLOSED_FINALIZED` and `BLOCKED` are terminal unless a new explicitly authorized runtime instance/context is created.

## 11. AAB seam

A runtime that declares an A-axis profile MUST route real side effects through enforcement external to the acting model.

Minimum flow:

1. agent proposes structured action;
2. trusted adapter resolves the effective action and security-relevant effects;
3. configured capability contract validates adapter-specific parameters/effects;
4. runtime binds the request to the active authenticated lease;
5. AAB validates lease validity/revocation, replay state, scope, credential/destination/effect ceilings, and cumulative budgets;
6. exact prepared-action hash is included in the chained authorization receipt;
7. durable state is committed before execution authority is released;
8. only `ALLOW` carrying the same action binding reaches the registered adapter;
9. the same immutable prepared object is dispatched.

`ESCALATE` is not authorization. `SIMULATE` may reach only a non-real-effect simulation path consistent with its profile.

## 12. Fail-closed action behavior

The following MUST NOT default to execution:

- missing/malformed policy or request;
- expired, not-yet-valid, revoked, or unverifiable lease;
- unknown credential or capability contract;
- out-of-scope target/destination/parameter/effect;
- replayed/stale request;
- budget exhaustion;
- uncertain durable state;
- authorization/execution-binding mismatch.

## 13. Transactional security state

An A2+ implementation with mutable replay/budget state MUST prevent concurrent authorization against the same stale state snapshot.

The reference uses a local SQLite transaction lock plus authenticated state reload/persist. Deployments may use different transactional mechanisms, but concurrent double spending of authority is non-conformant.

## 14. Rollback/fork evidence

A higher-assurance A2/A4 implementation SHOULD retain rollback evidence outside the protected local state. A newer state presented against an older checkpoint must prove ancestry, not merely claim a larger generation number.

## 15. Relationship to AMCS

AMCS remains a reference sealing/persistence protocol. AMCS 0.3.0 adds complete claimed v1.2.1 INTERNAL-profile surfaces, no-clobber sealed artifacts, content-root binding, optional HMAC root authentication, and generated-artifact conformance tests.

## 16. Status

This document is doctrine. Reference implementations demonstrate selected mechanics but do not establish production or frontier-model containment by themselves.
