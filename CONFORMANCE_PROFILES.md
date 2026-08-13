# AMAS Conformance Profiles

**Status:** Draft RC5  
**Purpose:** independent capability/evidence ladders for contextual-memory governance and agent action authority.

## 1. Scope

AMAS conformance is multi-axis. An implementation MUST NOT imply capabilities it does not implement or evidence categories it has not demonstrated.

- **C-axis:** contextual-memory/runtime lifecycle capability.
- **A-axis:** external action-authority enforcement capability.

Example claim: `AMAS C3/A2`.

## 2. Independent versioning

Conformance profiles version independently from AMAS Core, Runtime Binding, AMCS, and AAB. A claim SHOULD identify the exact specification/repository revision when reproducibility matters.

## 3. C-axis

### C1 — Read-Only Hydrate

- explicit memory load;
- provenance and semantic-role inspection;
- non-mutating review;
- no append, repair, or authoritative export.

### C2 — Hydrate + Validate

C1 plus:

- deterministic authority/semantic-role validation;
- conflict-arbitration validation;
- full preflight;
- invalid/quarantine identification;
- validation reports.

### C3 — Append-Capable

C2 plus:

- validated activation;
- append;
- derived-view regeneration;
- append receipts;
- no silent semantic-role/tier elevation;
- no silent repair/export.

### C4 — Persistent-Runtime Full Conformance

C3 plus:

- explicit repair/migration;
- validated export proof bundles;
- lifecycle-state handling;
- operator-visible verification;
- receipt discipline;
- terminal-state handling;
- durable lineage/canonical-state controls required by the declared runtime.

## 4. A-axis

### A0 — No action-boundary claim

No AMAS enforcement claim over external side effects.

### A1 — Observe / Simulate

Required:

- structured action requests;
- external policy evaluation;
- deny-by-default objective/operation/target scope;
- no real side effects beyond the declared observation/simulation boundary;
- decision receipts.

### A2 — Scoped Side Effects with Enforcement Integrity

A1 plus:

- destination/network and credential scope;
- adapter-specific capability-contract scope where parameters/effects can alter security semantics;
- side-effect ceilings;
- action/network/egress/time budgets;
- authenticated lease with issue/not-before/expiry semantics;
- defined revocation behavior;
- fail-closed malformed-request handling;
- nonce/sequence/freshness replay controls;
- broker-owned cumulative enforcement counters;
- transaction-safe mutable security state;
- exact effective-action binding inside tamper-evident decision evidence;
- durable persistence before executable authorization returns;
- documented mediation boundary.

An A2 claim does **not** prove that the agent lacks an unmediated equivalent-effect path.

### A3 — Bounded Delegation

A2 plus:

- machine-verified monotonic child-policy derivation;
- no child widening of objectives, operations, targets, destinations, credentials, capability-contract identifiers, side-effect ceilings, budgets, expiry, or delegation depth;
- parent/child provenance;
- child lease integrity protection;
- documented revocation/expiry propagation semantics.

### A4 — Adversarial Containment

A3 plus architecture-specific reproducible evidence demonstrating all of the following.

#### Authority violations are blocked

- objective/target substitution;
- destination expansion;
- ambient credential use;
- side-effect/privilege expansion;
- parameter/effect smuggling through allowed operations;
- budget expansion/reset;
- stale/replayed requests;
- lease tampering/premature use/revocation bypass;
- unauthorized delegation.

#### Enforcement state remains authoritative

- replay state and cumulative budgets survive restart;
- concurrent broker instances cannot double spend authority;
- state corruption/persistence uncertainty fails closed;
- restoration of older authenticated state is detected;
- a newer state must prove descent from the retained checkpoint/anchor or an equivalent stronger mechanism;
- decision-chain state and exact action bindings are independently reviewable.

#### Mediation is complete for the evaluated architecture

- every enumerated agent→effect path crosses the enforcement boundary;
- adapters, redirects, proxies, subprocesses, plugins, network routes, credentials, RPC paths, local-file effects, collaborating agents, and equivalent-effect channels are included in evaluation scope as applicable;
- modeled bypass paths fail evaluation;
- empirical testing demonstrates that the evaluated agent did not exercise an equivalent unmediated path.

#### Evidence is reproducible

- test corpus;
- model/provider/version;
- environment assumptions;
- enforcement topology;
- lease/policy/capability-contract configuration;
- results;
- failure criteria;
- known residual risks

are reviewable.

A4 is evidence-bearing. Documentation, policy prompts, a passing unit suite, or the existence of reference code alone is insufficient.

## 5. No hidden elevation

A runtime may not silently behave as or advertise a higher profile than declared. Capability and evidence must be explicit and reviewable.

## 6. Evidence categories

Conformance discussions SHOULD distinguish:

1. specified property;
2. implemented mechanism;
3. automated/adversarial test evidence;
4. deployment-specific evidence;
5. independent certification/evaluation.

A higher category must not be implied by a lower one.

## 7. Current repository position

The repository contains executable reference mechanisms exercising substantial A2/A3 requirements and A4 prerequisites, including:

- semantic-role-aware AMAS conflict arbitration;
- signed leases with validity windows and revocation hook;
- capability contracts;
- exact action-binding receipts;
- replay controls and broker-owned budgets;
- transactional durable state;
- state ancestry/checkpoints;
- monotonic delegation;
- structural mediation/bypass tests;
- adversarial vectors;
- hardened AMCS persistence/conformance tests.

It **does not claim certified A2/A3 deployment conformance or A4 containment of frontier models**. Those claims require evaluation of an actual deployed mediation architecture.
