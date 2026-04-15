# AMAS Conformance Profiles

Status: Draft RC1  
Purpose: capability ladder for runtime implementations operating under AMAS governance.

---

## 1. Scope

This document defines runtime capability profiles.
It does not redefine the AMAS governance core.

AMAS governance remains authoritative for:
- authority tiers
- canonicality rules
- mutation/export boundaries
- provenance and inference doctrine

This document defines what a runtime is allowed to do under those rules.

---

## 2. Independent Versioning

Conformance profiles version independently from:
- AMAS Core
- Runtime Binding doctrine

Reason:
- governance changes slowly
- runtime mechanics and certification surfaces change faster
- profile evolution should not force unnecessary governance rewrites

---

## 3. Profiles

### C1 — Read-Only Hydrate

Allowed:
- explicit memory load
- provenance inspection
- non-mutating review

Forbidden:
- append
- repair
- authoritative export

### C2 — Hydrate + Validate

Allowed:
- all C1 behavior
- full preflight validation
- invalid/quarantine identification
- validation reports

Forbidden:
- append
- repair
- mutated export

### C3 — Append-Capable

Allowed:
- all C2 behavior
- validated activation
- append
- derived-view regeneration
- append receipts

Forbidden:
- silent repair
- silent export
- mutation outside activation/preflight gates

### C4 — Persistent-Runtime Full Conformance

Allowed:
- all C3 behavior
- explicit repair workflows
- migration workflows
- validated export with proof bundles
- full lifecycle state handling

Required:
- full runtime-binding compliance
- operator-visible verification surfaces
- receipt discipline
- terminal-state handling

---

## 4. No Hidden Elevation

A runtime may not silently behave as a higher profile than the one it declares.

Rules:
- no hidden elevation
- no inferred capability promotion
- capability must be explicitly declared and reviewable

---

## 5. Certification Principle

A profile claim is credible only if:
- required gates are present
- required receipts are emitted
- operator-visible verification surfaces exist
- no forbidden silent behaviors are observed

---

## 6. Legacy Migration Appendix

AMAS v1.1 currently exposes legacy inline conformance levels:

- Level 1 (Minimal)
- Level 2 (Standard)
- Level 3 (Full)

Recommended transitional mapping:

- Level 1 ≈ C1
- Level 2 ≈ C2
- Level 3 spans C3 and C4

This is a migration guide, not an exact equivalence guarantee.
The old ladder should remain documented until the profile-based model is formally adopted as the canonical conformance surface.

---

## 7. Status

This file defines the separated conformance doctrine for the next generation of the AMAS specification.
It should be read alongside:
- `SPEC.md`
- `RUNTIME_BINDING.md`
