# AMAS — Authority Mapping and Arbitration System

**A formal governance and reference-enforcement architecture for contextual authority, durable memory, and bounded agent action.**

- **AMAS Core:** 2.0-draft, revision 2026-08-12
- **AAB extension:** 0.4.1-draft hardening line
- **AMCS reference runtime:** 0.3.3 implementing the tested AMCS v1.2.1 INTERNAL surfaces described below
- **Status:** research draft; open for review; no production-containment certification claim
- **Author:** Jacob Dougherty

## Design thesis

LLM and agent systems combine platform constraints, operator instructions, user directives, retrieved documents, tool output, memory, and model-generated inference. Tool-using agents add a separate failure mode: a model may discover that it *can* reach a resource and treat capability as authority.

AMAS separates these concepts explicitly:

- **data is not instruction**;
- **inference is not fact or delegation**;
- **reachability is not authorization**;
- **capability is not authority**;
- **successful execution does not widen scope**.

The repository contains three related surfaces:

1. **AMAS Core** — contextual/memory authority and deterministic arbitration.
2. **AMCS** — an immutable reference memory-cell persistence/sealing protocol under AMAS governance.
3. **AAB (Agent Authority Boundary)** — external action authority, mediation, replay/budget state, delegation, and execution binding.

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

| Role | Direct action/instruction authority? |
|---|---|
| `DIRECTIVE` | Yes, subject to tier, scope, and higher authority. |
| `EVIDENCE` | No. |
| `OBSERVATION` | No. |
| `INFERENCE` | No. |

Imperative text inside a retrieved document, tool result, quotation, or inference does not become a directive merely because it is phrased as a command.

### Deterministic conflict arbitration

After directive-role admissibility, conflicts are resolved in this order:

1. tier precedence;
2. explicit authenticated/provenance-bound supersession;
3. explicit scope specificity using structural `scope_path` prefix containment;
4. recency;
5. unresolved conflict → **HALT / ESCALATE**.

There is no model-selected fallback for an unresolved authority conflict.

See `SPEC.md`, `schemas/memory_object.schema.json`, `reference/conflict_resolution.py`, and `adversarial/amas_conflict_vectors.json`.

## Portable machine types

Normative wire values are language-neutral but restricted to domains that map without ambiguity to fixed-width C/C++ representations. Security integers remain within Canonical JSON v1's `±(2^53-1)` interoperability range, which is directly representable by `int64_t`/`uint64_t`; authority tiers and compact enums fit fixed-width byte-sized representations; hashes use 32-byte internal values and 64-character lowercase hexadecimal JSON strings; booleans remain distinct from integers.

See `docs/PORTABLE_TYPES.md` and `docs/CANONICAL_JSON.md`.

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
  - authenticated authority lease
  - not-before / expiry / revocation hook
  - nonce + monotonic request sequence
  - cumulative broker-owned budgets
  - adapter capability-contract scope
  - transactional durable state
  - state ancestry + rollback checkpoint
  - chained receipt including exact action hash
      |
      +------ DENY / ESCALATE / SIMULATE
      |
      v ALLOW with matching binding hash
TRUSTED ADAPTER.execute(same PreparedAction)
      |
      v
SIDE-EFFECT SINK
```

A strong deployment must additionally prove that the agent has no equivalent route to the effect that bypasses the broker.

### Adapter capability contracts

A coarse permission such as “read service X” is not enough when exploit semantics can be hidden inside parameters or secondary effects. The reference capability contract can constrain:

- allowed/required parameter keys;
- parameter value allowlists;
- effective destinations;
- credential references;
- redirect behavior;
- filesystem effects;
- subprocess effects;
- secondary network destinations.

The adapter remains part of the trusted computing base: it must report the effective action accurately.

### Durable state

`reference/durable_broker.py` uses authenticated JSON state plus a SQLite `BEGIN IMMEDIATE` sidecar transaction lock. Each authorization reloads the newest state while holding the lock, preventing cooperating broker processes from authorizing against the same stale budget/sequence snapshot.

State version 2 also carries `previous_state_hash` and an explicit ancestry list. A newer restored state is accepted against an older checkpoint only when the checkpointed state is in that lineage and the receipt chain extends the checkpoint tip.

This is a compact reference, not a recommendation to use local JSON/HMAC state as a production distributed security store.

## AMCS 0.3.3 / v1.2.1 INTERNAL

The AMCS reference runtime emits and verifies the currently tested v1.2.1 INTERNAL-profile surfaces, including:

- complete chat crawl;
- prompt/response causality with explicit `no_response_required` accounting;
- FIRST-ORDER messages matrix;
- case file(s);
- case-study map plus nodes/edges CSV;
- `cell_index.json`;
- copied machine schemas;
- verification log;
- content hash manifest;
- seal receipt;
- cryptographic cell-root binding of manifest + seal metadata + cell index;
- optional HMAC-authenticated root;
- immutable no-clobber cell/supercell creation;
- delta lineage fields;
- bounded traversal-safe archive extraction;
- child-cell verification before supercell assembly.

ODT canonical-narrative interpretation and richer cross-cell supercell reasoning remain subject to the AMCS conformance boundary and must not be inferred merely from archive/sealing support.

The optional HMAC mode is a reference authenticity mechanism. Production signing/anchoring keys should reside outside the model/runtime compromise domain.

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

**A4 is evidence-bearing.** Documentation, prompts, or reference code do not establish A4. It requires architecture-specific, reproducible evidence that the evaluated agent cannot exercise an equivalent unmediated path.

The repository does **not** claim certified A2/A3 deployment conformance or A4 containment of frontier models.

## Evidence currently in the repository

Automated tests cover, among other things:

- same-tier data-as-instruction attempts;
- deterministic scope arbitration and fail-closed conflict resolution;
- policy target/objective/destination/credential expansion;
- capability-contract parameter and secondary-effect violations;
- exact authorization-to-execution binding;
- signed lease tampering, not-before, revocation hooks, nonce replay, sequence violations, and budget exhaustion;
- monotonic child-policy delegation including capability-contract scope;
- durable restart/replay state;
- stale multi-process broker state serialization;
- checkpoint ancestry/rollback behavior;
- structural mediation bypass topologies;
- AMCS archive traversal, links/special files, expansion limits, attachment escape, no-clobber sealing, authenticated cell roots, prompt omission handling, delta lineage, generated-artifact schema validation, and supercell conformance.

Run:

```bash
python -m py_compile reference/*.py
python -m unittest discover -s tests -v
```

CI uses pinned GitHub Action commit SHAs and Python 3.11 with a pinned `jsonschema` test dependency.

## Repository layout

```text
SPEC.md                         AMAS Core doctrine
RUNTIME_BINDING.md              runtime binding contract
CONFORMANCE_PROFILES.md         C/A capability and evidence ladders
SECURITY.md                     security/evidence boundary

docs/AGENT_AUTHORITY_BOUNDARY.md
docs/EXECUTION_BINDING.md
docs/THREAT_MODEL.md
docs/AUTHORITY_LAUNDERING.md
docs/CANONICAL_JSON.md
docs/PORTABLE_TYPES.md
docs/DESIGN_RATIONALE.md

reference/amcs.py
reference/memory_object_validation.py
reference/conflict_resolution.py
reference/authority_gate.py
reference/enforcement_broker.py
reference/durable_broker.py
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

If the enforcement host, trusted adapter, signing authority, checkpoint service, operating system, hypervisor, or an unmodeled equivalent side-effect route is compromised, reference policy code cannot manufacture containment after the boundary has already failed.

## Claim discipline

A defensible current description is:

> **AMAS/AAB is a specified and executable authority-bounding reference architecture with reproducible tests for its documented mechanisms.**

This repository does **not** establish that AMAS/AAB contains arbitrary frontier models, nor that it would have prevented any specific historical incident in an untested architecture.

## Remaining evidence roadmap

- controlled provider/model mediated-agent harness;
- empirical equivalent-effect path enumeration;
- independent checkpoint-anchor adapter in a genuinely separate failure domain;
- multi-agent revocation/negotiation protocol across providers;
- independent external evaluation;
- publication/preprint package.

## License

Copyright (c) 2026 Jacob Dougherty. **All Rights Reserved.**

No open-source license is granted. See `LICENSE` for the repository notice.
