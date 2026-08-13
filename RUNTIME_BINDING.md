# AMAS Runtime Binding Contract

**Status:** Draft RC4  
**Purpose:** runtime mechanics that implement AMAS governance without changing AMAS Core doctrine.

## 1. Scope

AMAS Core defines authority, semantic role, canonicality, and conflict/mutation boundaries. Runtime Binding defines activation, validation, append, repair, export, state transitions, and the seam to AAB for external side effects.

## 2. Core/runtime separation

AMAS Core decides what counts as authoritative. Runtime Binding defines how those requirements are represented and verified at runtime. AMCS is one memory persistence reference. AAB separately governs external action authority.

## 3. Ingestion and semantic-role binding

Runtime ingestion MUST preserve enough trusted metadata to assign both `authority_tier` and `semantic_role` (`DIRECTIVE`, `EVIDENCE`, `OBSERVATION`, `INFERENCE`).

Imperative wording MUST NOT elevate `EVIDENCE`, `OBSERVATION`, or `INFERENCE` into a directive. Where one source contains distinct directives and quoted/evidentiary material, implementations SHOULD segment those units rather than let message boundaries silently transfer directive authority.

A non-directive → directive transition MUST create a new auditable object issued by a principal already authorized to create that directive.

Every Memory Object MUST pass the normative machine contract before participating in authority arbitration. A malformed high-tier object MUST NOT acquire authority merely because the subset of fields inspected by an implementation happens to look privileged.

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

Explicit supersession is an authority-bearing operation. A `supersedes` field and provenance metadata are not self-authenticating. Before Rule 2 resolves a conflict, the runtime MUST verify both structural traceability and authorization of the issuing actor for the superseded tier/scope through a trusted authority service/context outside the disputed Memory Object itself.

Missing, false, malformed, or unavailable supersession authorization MUST fail closed to Rule 5. A runtime MUST NOT add an undocumented probabilistic or model-selected tie-breaker.

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
- applicable action-decision chain tip where AAB is active;
- applicable completion/effect state for side effects that were dispatched.

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
5. AAB validates exact lease/policy shape, lease validity/revocation, replay state, scope, credential/destination/effect ceilings, and cumulative budgets;
6. exact prepared-action hash is included in the chained authorization receipt;
7. durable authorization state is committed before execution authority is released;
8. only `ALLOW` carrying the same action binding proceeds;
9. a durable completion record is written as `STARTED` before adapter dispatch;
10. the same immutable prepared object is dispatched;
11. adapter return becomes `SUCCEEDED`; post-dispatch uncertainty becomes `OUTCOME_UNKNOWN`.

`ESCALATE` is not authorization. `SIMULATE` may reach only a non-real-effect simulation path consistent with its profile.

`OUTCOME_UNKNOWN` is not proof of failure and MUST NOT be treated as an automatic-retry signal. A deployment SHOULD reconcile against the target system or use service-specific idempotency/transaction mechanisms where available.

## 12. Fail-closed action behavior

The following MUST NOT default to execution:

- missing/malformed policy, lease, request, or capability contract;
- expired, not-yet-valid, revoked, or unverifiable lease;
- unknown credential or capability contract;
- out-of-scope target/destination/parameter/effect;
- replayed/stale request;
- budget exhaustion;
- uncertain durable authorization state;
- authorization/execution-binding mismatch;
- inability to persist the pre-dispatch completion `STARTED` record;
- exhaustion of a declared bounded durable-state epoch.

Post-dispatch uncertainty is not represented as a pre-dispatch denial; it is recorded as `OUTCOME_UNKNOWN`.

## 13. Transactional security state

An A2+ implementation with mutable replay/budget state MUST prevent concurrent authorization against the same stale state snapshot.

The reference uses a local SQLite transaction lock plus authenticated state reload/persist. Deployments may use different transactional mechanisms, but concurrent double spending of authority is non-conformant.

The base reference retains complete replay/receipt/ancestry history for inspectability. `BoundedDurableEnforcementBroker` adds a finite epoch ceiling for long-lived use. Implementations MAY use compaction or external append-only logs, but MUST NOT silently discard replay/security evidence in a way that restores spent authority.

## 14. Rollback/fork evidence

A higher-assurance A2/A4 implementation SHOULD retain rollback evidence outside the protected local state. A newer state presented against an older checkpoint must prove ancestry, not merely claim a larger generation number.

## 15. Portable machine representation

Security-critical runtime fields SHOULD map to the fixed-width profile in `docs/PORTABLE_TYPES.md` / `include/amas/types.h`.

Native pointer values, platform-width `long`/`size_t`, or `time_t` MUST NOT become normative wire semantics. Canonical JSON security integers are intentionally restricted to `±(2^53-1)` even when an implementation stores them in `int64_t`/`uint64_t`.

## 16. Relationship to AMCS

AMCS remains a reference sealing/persistence protocol.

- `reference/amcs.py` is the low-level AMCS 0.3.3 archive/sealing engine.
- `reference/amcs_runtime.py` is the supported schema-validating conformance entrypoint for current reference claims.
- supported JSON message input is validated before sealing;
- generated normative JSON surfaces are validated against repository Draft 2020-12 schemas before a conformance seal/verify is accepted.

The current reference binds/copies an ODT but does not parse its document semantics into structured canonical narrative. Current supercell assembly verifies/bundles children but does not automate semantic contradiction discovery or cross-cell authority reconciliation. Those richer behaviors must not be implied by the existence of archive assembly.

## 17. Status

This document is doctrine. Reference implementations demonstrate selected mechanics but do not establish production certification or frontier-model containment by themselves.
