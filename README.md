# AMAS — Authority Mapping and Arbitration System

**A formal governance and reference-enforcement architecture for contextual authority, durable memory, and bounded agent action.**

> **Two different AMAS technologies share this acronym.** This repository's established root specification is **AMAS-AUTH — Authority Mapping and Arbitration System**. The separate **AMAS-MANIP — Adaptive Manipulation Analysis System** is a proposed manipulation/cognitive-integrity research technology associated with the AMAS–Symbalics work; its explanatory research materials are tracked separately under `research/amas-manip/`. The proposed **AMAS Integrity Plane** is an interface umbrella, not a third expansion. **Neither AMAS-MANIP nor Symbalics has an implemented/validated integrated runtime in this repository.** See `docs/AMAS_TECHNOLOGY_REGISTRY.md` and `docs/AMAS_SOURCE_LINEAGE.md`.


- **AMAS Core:** 2.0-draft, revision 2026-08-12
- **AAB extension:** 0.4.1-draft hardening line
- **AMCS reference engine:** 0.3.3, implementing the tested AMCS v1.2.1 INTERNAL surfaces described here
- **Status:** research draft; no production-containment certification claim
- **Author:** Jacob Dougherty
- **License:** All Rights Reserved

## Design thesis

LLM and agent systems combine platform constraints, operator instructions, user directives, retrieved documents, tool output, memory, and model-generated inference. Tool-using agents add another failure mode: a model may discover that it *can* reach a resource and treat capability as authority.

AMAS separates these concepts explicitly:

- **data is not instruction**;
- **inference is not fact or delegation**;
- **reachability is not authorization**;
- **capability is not authority**;
- **successful execution does not widen scope**;
- **authorization is not proof of completion**.

The repository contains three related surfaces:

1. **AMAS Core** — contextual/memory authority and deterministic arbitration.
2. **AMCS** — immutable reference memory-cell persistence/sealing under AMAS governance.
3. **AAB (Agent Authority Boundary)** — external action authority, mediation, replay/budget state, delegation, execution binding, and completion-state discipline.

## AMAS Core 2.0-draft

AMAS uses two independent classifications.

### Authority tiers

| Tier | Name | Meaning |
|---|---|---|
| 0 | CANONICAL | Foundational constraints and invariants. |
| 1 | OPERATOR | Deployer/application authority within Tier 0. |
| 2 | SESSION | User/runtime material within Tiers 0–1. |
| 3 | INFERRED | Model-derived inference; lowest authority. |

### Semantic roles

| Role | Direct instruction/action authority? |
|---|---|
| `DIRECTIVE` | Yes, subject to tier, scope, and higher authority. |
| `EVIDENCE` | No. |
| `OBSERVATION` | No. |
| `INFERENCE` | No. |

Imperative text inside retrieved material, tool output, quotations, or inference remains data unless an already-authorized actor creates a new directive through an explicit authority-bearing transition.

### Deterministic conflict arbitration

After semantic-role admissibility, conflicts resolve in this order:

1. tier precedence;
2. explicit supersession;
3. explicit scope specificity using structural `scope_path` prefix containment;
4. recency;
5. unresolved conflict → **HALT / ESCALATE**.

Explicit supersession is not trusted because a Memory Object merely names another object. The reference resolver requires both traceable authenticated provenance **and a trusted caller-supplied supersession authorizer** confirming that the actor held authority over the superseded tier/scope. Missing, false, malformed, non-boolean, or failing authorization checks fail closed.

See `SPEC.md`, `schemas/memory_object.schema.json`, `reference/memory_object_validation.py`, `reference/conflict_resolution.py`, and `adversarial/amas_conflict_vectors.json`.

## Portable machine types

Normative wire values are language-neutral but restricted to domains that map without ambiguity to fixed-width C/C++ representations.

- compact tiers/enums → `uint8_t`-compatible;
- counters/budgets → `uint64_t` internally, limited to Canonical JSON v1's exact `0..2^53-1` wire range;
- signed security integers → `int64_t` internally, limited to `±(2^53-1)` on the Canonical JSON wire;
- hashes → 32-byte internal value / 64-character lowercase hexadecimal JSON representation;
- UTF-8 and timestamps use explicit byte lengths/text representations rather than pointer values or platform-dependent `time_t` wire semantics;
- booleans are not interchangeable with integer `0/1`.

The repository provides `include/amas/types.h` plus C11 and C++17 compile checks. See `docs/PORTABLE_TYPES.md` and `docs/CANONICAL_JSON.md`.

## AAB 0.4.1-draft

AAB places action authorization outside the acting model.

```text
MODEL / AGENT
      |
      v
requested action
      |
      v
TRUSTED ADAPTER.prepare()
  - effective operation / target / destination
  - credential reference
  - security-relevant parameters/effects
  - broker-owned cost
      |
      v
immutable PreparedAction + SHA-256 binding
      |
      v
DURABLE AAB BROKER
  - exact authenticated lease shape
  - not-before / expiry / revocation hook
  - nonce + monotonic request sequence
  - cumulative broker-owned budgets
  - capability-contract scope
  - transactional durable state
  - state ancestry + rollback checkpoint
  - chained receipt including exact action hash
      |
      +------ DENY / ESCALATE / SIMULATE
      |
      v ALLOW
COMPLETION JOURNAL: STARTED
      |
      v
TRUSTED ADAPTER.execute(same PreparedAction)
      |
      +------ returned ------> SUCCEEDED
      |
      +------ uncertain -----> OUTCOME_UNKNOWN
```

A strong deployment must additionally prove that the agent has no equivalent route to the effect that bypasses the broker.

### Capability contracts

A coarse permission such as “read service X” is insufficient when security semantics can be hidden inside parameters or secondary effects. Content-addressed capability contracts can constrain:

- allowed/required parameter keys;
- parameter value allowlists;
- effective destinations;
- credential references;
- redirect behavior;
- filesystem effects;
- subprocess effects;
- secondary network destinations.

The adapter remains part of the trusted computing base and must report the effective action accurately.

### Authorization-to-completion integrity

`reference/mediated_executor.py` binds the exact prepared action into the broker's chained authorization receipt and requires a transactional completion journal before dispatch.

- journal failure before dispatch → no execution;
- adapter returns → `SUCCEEDED` even if the returned value itself cannot be serialized;
- adapter exception after dispatch → `OUTCOME_UNKNOWN`;
- a crash-recovered lingering `STARTED` record is treated as `OUTCOME_UNKNOWN`, not as safe-to-retry.

The filesystem-backed SQLite journal is the durable reference mode; `:memory:` exists only for tests. This mechanism does not create distributed exactly-once semantics for arbitrary external systems. See `docs/COMPLETION_INTEGRITY.md`.

### Durable state and bounded epochs

`reference/durable_broker.py` uses authenticated JSON state plus a SQLite `BEGIN IMMEDIATE` sidecar transaction lock. Each authorization reloads the newest state while holding the lock, preventing cooperating broker processes from authorizing against the same stale budget/sequence snapshot.

State version 2 carries `previous_state_hash` and ancestry evidence. `reference/bounded_durable_broker.py` adds a finite epoch ceiling so complete receipt/replay/ancestry state cannot grow without bound. Reaching the configured ceiling fails closed and requires explicit checkpoint/rotation rather than silent deletion of replay evidence.

These are compact references, not recommendations to use local JSON/HMAC/SQLite as a production distributed security store.

## AMCS 0.3.3 / v1.2.1 INTERNAL reference surfaces

`reference/amcs.py` is the low-level sealing/archive engine. **`reference/amcs_runtime.py` is the supported schema-validating conformance entrypoint.** It adds strict JSON-message admission and validates normative generated JSON surfaces against the repository's Draft 2020-12 schemas before a seal/verification is accepted.

The currently tested reference surfaces include:

- complete in-scope chat crawl;
- prompt/response causality and explicit `no_response_required` accounting;
- FIRST-ORDER messages matrix;
- case file(s);
- case-study map plus nodes/edges CSV;
- tensor summary with direct provenance;
- `cell_index.json`;
- copied schemas;
- verification log;
- content hash manifest;
- seal receipt;
- cryptographic cell-root binding;
- optional HMAC-authenticated root;
- immutable no-clobber cell/supercell creation;
- verified delta lineage;
- bounded traversal-safe extraction;
- child-cell verification before supercell assembly;
- generated JSON schema validation through `reference/amcs_schema_validation.py`.

### AMCS claim boundary

The reference engine may copy/bind an ODT and label it as the primary narrative source, but it does **not** yet parse ODT document semantics into a structured canonical narrative.

The supercell assembly helper verifies and bundles child cells with explicit hashes/scope/mode, but it does **not** yet automate cross-cell semantic contradiction discovery or authority reconciliation.

Therefore the supported claim is that AMCS 0.3.3 implements the **tested reference surfaces listed above**, not that every richer semantic behavior described in AMCS v1.2.1 is fully automated.

## Conformance axes

### C-axis — memory/runtime

- `C1` read-only hydrate
- `C2` hydrate + validate
- `C3` append-capable
- `C4` persistent-runtime full conformance

### A-axis — action authority

- `A0` no action-boundary claim
- `A1` observe/simulate
- `A2` scoped side effects with enforcement integrity
- `A3` bounded monotonic delegation
- `A4` adversarial containment evidence

**A4 is evidence-bearing.** Documentation, prompts, reference code, or a passing unit suite do not establish A4. It requires architecture-specific, reproducible evidence that the evaluated agent cannot exercise an equivalent unmediated path.

The repository does **not** claim certified A2/A3 deployment conformance or A4 containment of frontier models.

## Automated evidence

The conformance suite covers, among other things:

- same-tier data-as-instruction attempts;
- deterministic scope arbitration and fail-closed conflicts;
- full Memory Object admission;
- externally authorized supersession;
- policy target/objective/destination/credential expansion;
- content-addressed capability contracts and secondary-effect violations;
- exact authorization-to-execution binding;
- completion `SUCCEEDED` / `OUTCOME_UNKNOWN` behavior;
- exact signed lease admission, freshness, revocation, nonce replay, sequence, and budgets;
- monotonic child delegation and parent-hash binding;
- durable restart/replay/concurrency/checkpoint ancestry;
- bounded durable epochs;
- structural mediation bypass topologies;
- Canonical JSON cross-runtime rules;
- C11/C++17 portable-type compilation;
- AMCS traversal/link/expansion/attachment/no-clobber/root/delta/supercell behaviors;
- schema-validating AMCS round trips.

Run:

```bash
python -m pip install -r requirements.txt
python -m py_compile reference/*.py
cc -std=c11 -Wall -Wextra -Werror -pedantic -Iinclude -fsyntax-only tests/c_portability_smoke.c
c++ -std=c++17 -Wall -Wextra -Werror -pedantic -Iinclude -fsyntax-only tests/cpp_portability_smoke.cpp
python -m unittest discover -s tests -v
```

CI uses pinned GitHub Action commit SHAs, Python 3.11, pinned dependencies, and runs on `main`, pull requests targeting `main`, and `hardening/**` pushes.

## Repository layout

```text
SPEC.md                         AMAS Core doctrine
RUNTIME_BINDING.md              generalized runtime binding
CONFORMANCE_PROFILES.md         C/A capability and evidence ladders
SECURITY.md                     security/evidence boundary
LICENSE                         proprietary All Rights Reserved notice
CONTRIBUTING.md                 review/contribution rights posture
requirements.txt                pinned Python conformance dependency

include/amas/types.h             C/C++ portable type profile

docs/AGENT_AUTHORITY_BOUNDARY.md
docs/EXECUTION_BINDING.md
docs/COMPLETION_INTEGRITY.md
docs/THREAT_MODEL.md
docs/AUTHORITY_LAUNDERING.md
docs/CANONICAL_JSON.md
docs/PORTABLE_TYPES.md
docs/DESIGN_RATIONALE.md

reference/amcs.py                low-level AMCS engine
reference/amcs_runtime.py        supported AMCS conformance entrypoint
reference/amcs_schema_validation.py
reference/memory_object_validation.py
reference/conflict_resolution.py
reference/authority_gate.py
reference/enforcement_broker.py
reference/durable_broker.py
reference/bounded_durable_broker.py
reference/capability_contract.py
reference/mediated_executor.py
reference/delegation.py
reference/mediation_graph.py
reference/receipt_chain.py

schemas/
adversarial/
tests/
```

## Security boundary

AMAS/AAB does not replace infrastructure security. A real deployment also requires conventional controls such as process/namespace isolation, egress filtering, least-privilege identity, secret isolation, controlled subprocess/plugin surfaces, accurate endpoint resolution, independent logs/checkpoints, and complete enumeration of equivalent-effect channels.

If the enforcement host, trusted adapter, signing authority, persistence/checkpoint service, operating system, hypervisor, or an unmodeled equivalent side-effect route is compromised, reference policy code cannot manufacture containment after the boundary has failed.

## Claim discipline

A defensible current description is:

> **AMAS/AAB is a specified and executable authority-bounding reference architecture with reproducible tests for its documented mechanisms.**

This repository does **not** establish that AMAS/AAB contains arbitrary frontier models, nor that it would have prevented any specific historical incident in an untested architecture.

## Remaining evidence roadmap

- controlled provider/model mediated-agent harness;
- empirical equivalent-effect path enumeration;
- independent checkpoint anchor in a genuinely separate failure domain;
- multi-agent revocation/negotiation protocol across providers;
- independent external evaluation;
- publication/preprint package.

## License

Copyright (c) 2026 Jacob Dougherty. **All Rights Reserved.**

No open-source license is granted. See `LICENSE`. This licensing posture remains in effect until the copyright holder explicitly changes it.
