# AMAS Conformance Profiles

Status: Draft RC2  
Purpose: independent capability ladders for memory/runtime governance and agent action authority.

## 1. Scope

AMAS conformance is multi-axis. An implementation MUST NOT imply capabilities it does not implement.

- **C-axis:** memory/runtime lifecycle capability.
- **A-axis:** external action-authority enforcement capability.

Example declaration: `AMAS C3/A2`.

## 2. Independent versioning

Conformance profiles version independently from AMAS Core, Runtime Binding, AMCS, and AAB. Governance changes slowly; runtime and certification surfaces may evolve faster.

## 3. C-axis — memory/runtime profiles

### C1 — Read-Only Hydrate
Allowed: explicit memory load, provenance inspection, non-mutating review.  
Forbidden: append, repair, authoritative export.

### C2 — Hydrate + Validate
C1 plus full preflight validation, invalid/quarantine identification, validation reports.  
Forbidden: append, repair, mutated export.

### C3 — Append-Capable
C2 plus validated activation, append, derived-view regeneration, append receipts.  
Forbidden: silent repair/export and mutation outside activation/preflight gates.

### C4 — Persistent-Runtime Full Conformance
C3 plus explicit repair, migration, validated export/proof bundles, lifecycle-state handling. Requires Runtime Binding compliance, operator-visible verification, receipt discipline, and terminal-state handling.

## 4. A-axis — action-boundary profiles

### A0 — No action-boundary claim
The implementation does not claim AMAS enforcement over external side effects.

### A1 — Observe / Simulate
Required:
- structured action requests
- external policy evaluation
- deny-by-default target and operation scope
- no real side effects beyond observation
- decision receipts

### A2 — Scoped Side Effects
A1 plus:
- explicit destination/network scope
- credential scope
- side-effect ceilings
- time/action/network/egress budgets
- policy expiration
- fail-closed malformed-request handling

### A3 — Bounded Delegation
A2 plus:
- machine-verified monotonic child-policy derivation
- no child authority widening
- delegation-depth accounting
- provenance across parent/child authority leases

### A4 — Adversarial Containment
A3 plus evidence from an adversarial test corpus demonstrating:
- target-substitution denial
- destination-expansion denial
- ambient-credential denial
- privilege-expansion denial
- budget/rate-expansion denial
- unauthorized sub-agent/delegation denial
- model inability to bypass the external enforcement path in the evaluated architecture
- tamper-evident decision logging

A4 is an evidence-bearing profile. Documentation alone is insufficient.

## 5. No hidden elevation

A runtime may not silently behave as a higher profile than declared. Capability must be explicit and reviewable.

## 6. Certification principle

A conformance claim is credible only if required gates exist, required receipts are emitted, forbidden silent behaviors are absent, and tests are reproducible.

## 7. Legacy migration

AMAS v1.1 exposed legacy Levels 1–3. Transitional mapping:

- Level 1 ≈ C1
- Level 2 ≈ C2
- Level 3 spans C3/C4

The legacy ladder did not define A-axis action containment and therefore implies no A-level.

## 8. Current repository claim

The repository contains reference artifacts sufficient to exercise portions of A2 behavior, but **does not claim certified A2 or A4 containment of frontier models**. Independent evaluation remains required.
