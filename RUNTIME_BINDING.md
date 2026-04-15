# AMAS Runtime Binding Contract

Status: Draft RC1  
Purpose: define runtime mechanics that implement AMAS governance without changing AMAS core doctrine.

---

## 1. Scope

AMAS governance defines authority, canonicality, and mutation boundaries.
This document defines the runtime mechanics that operate under those rules.

This contract governs:
- activation
- preflight validation
- append mechanics
- repair mechanics
- export mechanics
- runtime state transitions
- operator-visible verification surfaces

This contract does not:
- redefine the AMAS four-tier authority ladder
- replace the AMAS five-rule conflict protocol
- overwrite AMCS-specific implementation details
- claim current implementation conformance beyond what public artifacts demonstrate

---

## 2. Relationship to AMAS Core

AMAS Core remains the authoritative governance layer.

AMAS Core decides:
- what counts as authoritative
- what may mutate
- what must never be silently rewritten
- what conditions must be satisfied before mutation or export

Runtime Binding decides:
- how those rules are enforced at runtime
- what activation payloads are required
- what receipts and proof bundles are emitted
- what runtime states are legal

---

## 3. Activation Contract

No mutation may occur without validated activation.

### 3.1 Minimum activation fields

A valid activation contract MUST expose:

- `canonical_root_id` or `canonical_root_hash`
- `root_uniqueness_asserted`
- `writable_ledger_id` or `writable_ledger_path`
- `conformance_profile`
- `append_enabled`
- `repair_enabled`
- `activation_timestamp`
- `activation_receipt_hash`

### 3.2 Activation semantics

Activation is the boundary where a read-only hydrated context becomes mutation-capable.
If activation cannot be verified, the runtime remains non-mutating.

---

## 4. Preflight Validation

Preflight must pass before append, repair, or export.

### 4.1 Blocking checks

The runtime binding should treat these as blocking checks:

- canonical root uniqueness
- writable truth-ledger uniqueness
- chain-tip integrity
- schema compatibility
- manifest/hash consistency

### 4.2 Advisory checks

The runtime binding may surface these as advisory:

- wrapper sync status
- derived view sync status
- quarantine candidates present

---

## 5. Append Protocol

Append operations extend state without rewriting prior authoritative state.

### 5.1 Required sequence

1. stage
2. validate
3. hash
4. commit
5. regenerate derived views
6. emit receipt

### 5.2 Append invariants

- provenance must be preserved
- lineage must be preserved
- silent mutation is forbidden

---

## 6. Repair Protocol

Repair is a privileged operation because it can alter the operational representation of state.

### 6.1 Allowed repair classes

- wrapper regeneration
- derived ledger rebuild
- chain-tip correction with provenance
- migration with preserved provenance

### 6.2 Repair restrictions

- silent repair is forbidden
- silent chain-tip replacement is forbidden
- all repairs require receipts

---

## 7. Invalid Cell Handling

Invalid or unprovenanced memory does not activate under AMAS Core.

The runtime binding may additionally support:
- quarantine of invalid cells
- quarantine review workflows

Quarantine support is optional.
Activation of invalid cells is not allowed.

---

## 8. Export Proof Bundle

No export should proceed without conformance validation.

### 8.1 Minimum proof bundle

A runtime binding should expose:

- conformance profile
- chain-tip hash
- ledger digest
- export timestamp
- export receipt hash
- operator-visible state hash

This bundle allows the operator to inspect what was exported and under which state.

---

## 9. Runtime State Machine

The runtime binding defines the following states:

- `READ_ONLY_HYDRATE`
- `VALIDATING`
- `BIND_READY`
- `APPEND_READY`
- `REPAIR_READY`
- `EXPORT_READY`
- `CLOSED_FINALIZED`
- `BLOCKED`

### 9.1 Terminal states

- `CLOSED_FINALIZED`
- `BLOCKED`

A finalized state prevents ambiguous late-lifecycle mutation or re-export behavior.

---

## 10. Operator-Visible Verification Seam

The runtime binding must expose a reviewable verification seam to the operator.

Recommended verification surfaces:
- activation receipt
- ledger digest
- export receipt
- operator-visible state hash

This prevents runtime bookkeeping from becoming invisible authority.

---

## 11. Relationship to AMCS

AMCS is a reference runtime and sealing protocol operating under AMAS governance.

Where AMCS provides implementation-specific mechanics, those remain implementation-specific.
Where AMAS Runtime Binding defines generalized runtime doctrine, future AMCS revisions should align where applicable.

---

## 12. Status

This document is a doctrine artifact.
It is not, by itself, a claim that current public implementations already satisfy every runtime-binding rule defined here.
