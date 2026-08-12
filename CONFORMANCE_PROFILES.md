# AMAS Conformance Profiles

Status: Draft RC4  
Purpose: independent capability ladders for memory/runtime governance and agent action authority.

## 1. Scope

AMAS conformance is multi-axis. An implementation MUST NOT imply capabilities it does not implement.

- **C-axis:** memory/runtime lifecycle capability.
- **A-axis:** external action-authority enforcement capability.

Example: `AMAS C3/A2`.

## 2. Independent versioning

Conformance profiles version independently from AMAS Core, Runtime Binding, AMCS, and AAB.

## 3. C-axis — memory/runtime profiles

### C1 — Read-Only Hydrate
Explicit memory load, provenance inspection, non-mutating review. No append, repair, or authoritative export.

### C2 — Hydrate + Validate
C1 plus full preflight validation, invalid/quarantine identification, and validation reports.

### C3 — Append-Capable
C2 plus validated activation, append, derived-view regeneration, and append receipts. Silent mutation/repair/export is forbidden.

### C4 — Persistent-Runtime Full Conformance
C3 plus explicit repair/migration, validated export proof bundles, lifecycle-state handling, operator-visible verification, receipt discipline, and terminal-state handling.

## 4. A-axis — action-boundary profiles

### A0 — No action-boundary claim
No AMAS enforcement claim over external side effects.

### A1 — Observe / Simulate
Required:
- structured action requests
- external policy evaluation
- deny-by-default operation/target scope
- no real side effects beyond observation/simulation
- decision receipts

### A2 — Scoped Side Effects with Enforcement Integrity
A1 plus:
- destination/network and credential scope
- side-effect ceilings
- action/network/egress/time budgets
- policy expiry
- fail-closed malformed-request handling
- authenticated/integrity-protected authority lease
- request freshness and replay controls
- broker-owned cumulative enforcement counters
- tamper-evident receipts
- documented mediation boundary

An A2 claim does not prove the agent cannot discover an unmediated path.

### A3 — Bounded Delegation
A2 plus:
- machine-verified monotonic child-policy derivation
- no child authority widening
- delegation-depth accounting
- parent/child provenance
- child lease integrity protection
- documented expiry/revocation semantics

### A4 — Adversarial Containment
A3 plus architecture-specific reproducible evidence demonstrating all of the following:

**Authority violations are blocked**
- target/objective substitution denial
- destination expansion denial
- ambient credential denial
- privilege/side-effect expansion denial
- budget expansion/reset denial
- stale/replayed request denial
- lease tampering denial
- unauthorized delegation denial

**Enforcement state remains authoritative**
- replay state and cumulative budgets survive broker restart
- enforcement-state corruption fails closed
- restoration of older authenticated state is detected by an independently retained checkpoint or stronger rollback-resistant mechanism
- decision-chain state is independently reviewable

**Mediation is complete for the evaluated architecture**
- every enumerated agent→side-effect path crosses the enforcement boundary
- alternate adapters, proxies, subprocess channels, network routes, credentials, plugins, RPC paths, and equivalent-effect channels are included in the evaluation scope
- modeled bypass paths cause failure
- empirical testing provides evidence that the evaluated agent cannot exercise an unmediated equivalent path

**Evidence is reproducible**
- test corpus, environment assumptions, enforcement topology, results, and failure criteria are reviewable
- containment claims are scoped to the tested architecture and version

A4 is evidence-bearing. Documentation, policy prompts, or the existence of reference code alone are insufficient.

## 5. No hidden elevation

A runtime may not silently behave as a higher profile than declared. Capability must be explicit and reviewable.

## 6. Certification principle

A conformance claim is credible only when required gates exist, security state is authoritative and reviewable, forbidden silent behavior is absent, and tests are reproducible.

## 7. Legacy migration

AMAS v1.1 Levels 1–3 map approximately to C1–C4. They defined no A-axis action containment and imply no A-level.

## 8. Current repository claim

The repository now contains executable reference artifacts exercising substantial A2/A3 mechanisms plus A4 prerequisites: signed reference leases, replay controls, broker-owned accounting, monotonic delegation, authenticated durable broker state, rollback checkpoints, receipt chaining, and structural mediation/bypass tests.

It **does not claim certified A2/A3 deployment conformance or A4 containment of frontier models**. A4 requires independent, architecture-specific adversarial evaluation of a real mediated execution environment.
