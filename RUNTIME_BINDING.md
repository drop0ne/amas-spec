# AMAS Runtime Binding Contract

Status: Draft RC2  
Purpose: runtime mechanics that implement AMAS governance without changing AMAS Core doctrine.

## 1. Scope

AMAS Core defines authority, canonicality, and mutation boundaries. Runtime Binding defines activation, preflight, append, repair, export, state transitions, operator-visible verification, and the seam to the Agent Authority Boundary (AAB).

## 2. Core/runtime separation

AMAS Core decides what counts as authoritative and what must not be silently rewritten. Runtime Binding defines how those constraints are represented and verified at runtime. AAB separately governs proposed external side effects.

## 3. Activation contract

No mutation may occur without validated activation. A valid activation contract MUST expose a canonical root identifier/hash, root-uniqueness assertion, writable-ledger identifier/path, conformance profile, append/repair flags, activation timestamp, and activation receipt hash.

If activation cannot be verified, the runtime remains non-mutating.

## 4. Preflight

Blocking checks SHOULD include canonical-root uniqueness, writable-ledger uniqueness, chain-tip integrity, schema compatibility, and manifest/hash consistency. Advisory checks may include derived-view synchronization and quarantine candidates.

## 5. Append

Required sequence: stage → validate → hash → commit → regenerate derived views → emit receipt.

Append MUST preserve provenance and lineage. Silent mutation is forbidden.

## 6. Repair

Repair is privileged. Allowed classes include wrapper regeneration, derived-ledger rebuild, provenance-preserving chain-tip correction, and migration. Silent repair is forbidden and every repair requires a receipt.

## 7. Invalid memory

Invalid or unprovenanced memory does not activate. Quarantine/review workflows are optional; activation of invalid memory is not.

## 8. Export proof bundle

No authoritative export should proceed without conformance validation. A proof bundle SHOULD expose conformance profile, chain-tip hash, ledger digest, export timestamp, export receipt hash, and operator-visible state hash.

## 9. Runtime states

Suggested states:

- `READ_ONLY_HYDRATE`
- `VALIDATING`
- `BIND_READY`
- `APPEND_READY`
- `REPAIR_READY`
- `EXPORT_READY`
- `CLOSED_FINALIZED`
- `BLOCKED`

`CLOSED_FINALIZED` and `BLOCKED` are terminal.

## 10. Operator-visible verification

The runtime MUST expose reviewable verification surfaces appropriate to its declared profile: activation receipt, ledger digest, export receipt, state hash, and where AAB is active, action-decision receipts.

## 11. Agent Authority Boundary seam

A runtime that exposes tools or external side effects and declares an A-axis profile MUST route proposed side effects through an enforcement component external to the acting model.

The minimum request/decision flow is:

1. model/agent proposes structured action
2. runtime binds request to the active authority lease
3. AAB validates policy freshness and scope
4. AAB returns `ALLOW`, `DENY`, `ESCALATE`, or `SIMULATE`
5. only `ALLOW` reaches the real side-effecting tool path
6. decision receipt is persisted or exposed to the operator

`SIMULATE` may reach a non-side-effecting simulation environment only. `ESCALATE` is not authorization.

The acting model MUST NOT be able to mutate its own authority lease through ordinary tool output or model-generated inference.

## 12. Fail-closed behavior

For A-axis runtimes, missing policy, malformed request, expired lease, unknown credential, exceeded hard budget, or unverifiable principal binding MUST NOT default to execution.

## 13. Relationship to AMCS

AMCS remains a reference sealing/persistence protocol. AAB is a separate reference enforcement surface. Implementations may use either or both under AMAS Core governance.

## 14. Status

This document is doctrine. Reference implementations demonstrate selected mechanics but do not, by themselves, establish production conformance or frontier-model containment.
