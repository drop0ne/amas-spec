# AMAS — Authority Mapping and Arbitration System

**A formal governance model for contextual authority, memory authority, and bounded agent action.**

AMAS Core version: **2.0-draft**  
AAB extension version: **0.4-draft**  
Status: Open for review  
Author: Jacob Dougherty  
License: Apache 2.0

---

## Why AMAS Exists

LLM systems combine instructions, retrieved data, memory, tool results, and model-generated inference inside one operational context. Tool-using agents add a second failure mode: a model may discover that it **can** perform an action and incorrectly treat capability or reachability as permission.

AMAS separates:

- data from instruction
- inference from fact
- reachability from authorization
- capability from authority
- successful execution from permission to widen scope

The repository contains two complementary control planes:

1. **AMAS Core** — contextual and memory authority.
2. **AAB (Agent Authority Boundary)** — external action authority and enforcement-path integrity.

> **No lower-authority source, inference, newly discovered capability, or successful action may silently acquire greater authority.**

---

## AMAS Core

AMAS defines four contextual authority tiers:

| Tier | Name | Description |
|---|---|---|
| 0 | **CANONICAL** | Foundational constraints and system invariants. |
| 1 | **OPERATOR** | Developer/deployer instructions and configuration. |
| 2 | **SESSION** | User input, retrieved content, tool outputs, uploads, runtime context. |
| 3 | **INFERRED** | Model-derived conclusions. Lowest authority. |

Conflict resolution applies, in order:

1. tier precedence
2. explicit supersession
3. recency
4. specificity
5. conservative default / operator resolution

AMAS Core also defines canonical-root uniqueness, single writable truth-ledger discipline, explicit memory activation, provenance-gated hydration, mutation/repair controls, export receipts, and sealed-memory durability.

See [`SPEC.md`](SPEC.md), [`RUNTIME_BINDING.md`](RUNTIME_BINDING.md), and [`CONFORMANCE_PROFILES.md`](CONFORMANCE_PROFILES.md).

---

## AAB — Agent Authority Boundary

AAB requires an enforcement boundary external to the acting model.

```text
MODEL / AGENT
      |
      v
Structured Action Request
      |
      v
+------------------------------+
| durable AAB enforcement      |
| - signed authority lease     |
| - nonce / sequence state     |
| - broker-owned counters      |
| - AAB policy gate            |
| - persisted receipt chain    |
| - rollback checkpoint check  |
+---------------+--------------+
                |
        ALLOW / DENY
                |
                v
          Tool Adapter
                |
                v
        Side-Effect Sink

Independent checkpoint anchor <--- state hash / receipt-chain tip
```

A strong deployment must also establish that the model has no alternate route to an equivalent side effect that avoids this broker.

### Core AAB invariants

- Capability is not authority.
- Reachability is not authorization.
- Data is not instruction.
- Inference is not delegation.
- Success does not widen scope.
- No ambient credentials or privileges.
- Delegation may narrow but never silently broaden.
- Missing, expired, stale, replayed, unverifiable, or non-durable authority fails closed.
- The model is not the sole judge of its own authorization.
- Enforcement counters and replay state are broker-owned.
- Broker restart must not reset authority state.
- Older authenticated broker state must be detectable through independent checkpointing for higher assurance.
- Every modeled agent→side-effect path must cross the enforcement boundary.
- Higher containment claims require reproducible evidence.

See [`docs/AGENT_AUTHORITY_BOUNDARY.md`](docs/AGENT_AUTHORITY_BOUNDARY.md).

---

## Reference Components

### `reference/authority_gate.py`

Deny-by-default policy evaluation for:

- objective / operation / target scope
- destination/network scope
- credential scope
- side-effect ceilings
- policy expiry
- action/network/egress/time budgets
- delegation-depth limits
- explicit operator escalation

The gate evaluates requests; it does not execute them.

### `reference/enforcement_broker.py` — AAB 0.3

Moves enforcement-critical state outside the acting model:

- authenticated reference authority leases
- lease binding
- nonce replay protection
- monotonic request sequence
- request freshness checks
- broker-owned cumulative budgets
- broker-bound trusted action cost
- chained decision receipts

### `reference/durable_broker.py` — AAB 0.4

Adds authenticated durable security state:

- persisted usage/replay/sequence state
- persisted receipt chain
- state generations
- state hash + integrity MAC
- atomic replacement with fsync-based reference persistence
- restart recovery
- independently signable rollback checkpoints
- rollback detection when restored state is older than the retained checkpoint

A persistence failure is fail-closed. A caller must not perform the requested side effect until durable authorization returns successfully.

### `reference/mediation_graph.py` — AAB 0.4

Statically checks the declared enforcement topology. Every path from an `agent` node to a `side_effect` node must include a `broker` before the sink.

This identifies modeled bypass routes such as:

- direct agent→effect access
- alternate adapters
- proxy bypasses
- multi-agent bypasses
- multiple sinks where only one is mediated

It is structural evidence over the declared graph, not proof that the graph completely captures the deployed system.

### `reference/delegation.py`

Machine-verifies monotonic child-policy derivation. A child policy cannot widen objectives, operations, targets, destinations, credentials, side-effect ceiling, budgets, expiration, or delegation depth.

### `reference/receipt_chain.py`

Creates and verifies SHA-256-linked decision receipts. Receipt-chain tips can be bound into AAB 0.4 checkpoints.

---

## Adversarial Evidence

### Policy/enforcement vectors

`adversarial/aab_vectors.json` covers:

- principal impersonation
- objective substitution
- operation expansion
- target substitution
- destination expansion
- ambient credential use
- side-effect escalation
- budget overruns
- unauthorized delegation
- malformed requests
- boundary conditions

AAB 0.3 broker tests additionally cover:

- lease tampering
- nonce replay
- sequence gaps
- stale/future requests
- counter spoofing
- cumulative budget exhaustion
- receipt mutation

### Bypass topology vectors — AAB 0.4

`adversarial/bypass_topologies.json` adds reproducible topology checks for:

- direct bypass
- alternate adapter bypass
- indirect proxy bypass
- multi-agent bypass
- broker-after-effect invalid placement
- multi-sink partial mediation
- mediated cycles
- unreachable sinks that do not constitute functional containment proof

### Durable-state tests — AAB 0.4

`tests/test_durable_broker.py` exercises:

- restart persistence
- replay denial after restart
- authenticated state-tamper detection
- signed checkpoint verification
- checkpoint-tamper detection
- rollback detection using an older still-valid state image

These tests establish specific properties of the reference mechanisms. They do **not** establish frontier-model containment.

---

## Run Tests

```bash
python3 -m py_compile reference/*.py
python3 -m unittest discover -s tests -v
```

Existing policy-gate demonstration:

```bash
python3 reference/authority_gate.py \
  --policy examples/authority_policy.json \
  --requests examples/action_requests.json
```

---

## AMCS Memory Runtime

AMCS (Atticus Memory Cell Sealing Protocol) is the reference persistence/sealing runtime operating under AMAS memory governance.

```bash
python3 reference/amcs.py seal \
  --input examples/chat_minimal.json \
  --out-dir out \
  --cell-name DEMO_CELL

python3 reference/amcs.py verify --cell out/DEMO_CELL.tar.gz
```

- **AMCS** — memory provenance, sealing, integrity, rehydration.
- **AAB** — external action authority and enforcement integrity.

---

## Conformance

AMAS uses independent capability axes.

### C-axis — memory/runtime

- `C1` — read-only hydrate
- `C2` — hydrate + validate
- `C3` — append-capable
- `C4` — persistent-runtime full conformance

### A-axis — action authority

- `A0` — no action-boundary claim
- `A1` — observe/simulate
- `A2` — scoped side effects with enforcement integrity
- `A3` — bounded delegation
- `A4` — adversarial containment

A4 is explicitly evidence-bearing. AAB 0.4 supplies additional prerequisites for A4—durable broker state, rollback evidence, and mediation-graph testing—but the repository does **not** claim certified A4 containment.

See [`CONFORMANCE_PROFILES.md`](CONFORMANCE_PROFILES.md).

---

## Repository Structure

```text
amas-spec/
├── README.md
├── SPEC.md
├── RUNTIME_BINDING.md
├── CONFORMANCE_PROFILES.md
├── docs/
│   ├── AGENT_AUTHORITY_BOUNDARY.md
│   ├── AUTHORITY_LAUNDERING.md
│   ├── THREAT_MODEL.md
│   └── DESIGN_RATIONALE.md
├── reference/
│   ├── amcs.py
│   ├── authority_gate.py
│   ├── enforcement_broker.py
│   ├── durable_broker.py
│   ├── mediation_graph.py
│   ├── delegation.py
│   └── receipt_chain.py
├── schemas/
│   ├── memory_object.schema.json
│   ├── authority_policy.schema.json
│   ├── signed_authority_lease.schema.json
│   ├── broker_action_request.schema.json
│   ├── broker_state.schema.json
│   ├── broker_checkpoint.schema.json
│   ├── decision_receipt.schema.json
│   └── ...
├── adversarial/
│   ├── aab_vectors.json
│   └── bypass_topologies.json
├── tests/
│   ├── test_authority_gate.py
│   ├── test_enforcement_broker.py
│   ├── test_durable_broker.py
│   ├── test_mediation_graph.py
│   ├── test_delegation.py
│   └── test_adversarial_vectors.py
└── .github/workflows/ci.yml
```

---

## Threat / Trust Boundary

AMAS/AAB does not replace infrastructure security. Strong deployment also requires conventional controls such as:

- process and namespace isolation
- egress filtering
- least-privilege identities
- secret isolation
- independent logs/monitoring
- controlled subprocess and plugin paths
- enumerated equivalent-effect channels
- external checkpoint/key protection

If the enforcement plane or an unmodeled equivalent side-effect path is compromised, AAB cannot manufacture containment after the boundary has already been bypassed.

---

## Current Evidence Position

The repository contains executable mechanisms for substantial A2/A3 behavior and several A4 prerequisites.

It does **not** claim:

- certified production conformance
- proven frontier-model containment
- completeness of any real deployment's side-effect topology

The next evidence step is a controlled mediated-agent harness where a capable model is intentionally encouraged to discover alternate action paths while the surrounding environment independently records whether every equivalent side effect remains broker-mediated.

---

## Roadmap

- [x] AMAS governance core and runtime split
- [x] AMCS reference sealing runtime
- [x] AAB external action-authority gate
- [x] monotonic delegation verifier
- [x] adversarial policy vector corpus
- [x] signed reference leases
- [x] broker-owned cumulative budgets/replay state
- [x] durable authenticated broker state
- [x] independently signable rollback checkpoints
- [x] structural mediation/bypass corpus
- [ ] JSON Schema instance validation in CI
- [ ] deterministic Rule 4 specificity vectors
- [ ] checkpoint anchor adapter for a genuinely separate failure domain
- [ ] controlled provider/model mediated-agent harness
- [ ] empirical equivalent-effect path enumeration
- [ ] multi-agent authority negotiation protocol
- [ ] independent external evaluation
- [ ] publication/preprint package

---

## Design Position

AMAS is not a claim that instruction-following makes an agent trustworthy.

The architecture assumes a capable agent can misunderstand, optimize around an evaluator, follow hostile retrieved instructions, or discover unintended capabilities. For consequential actions, the authority boundary therefore belongs **outside the model**.

---

## Citation

```text
Dougherty, J. (2026). AMAS: Authority Mapping and Arbitration System.
Draft specification and reference architecture.
```

## License

Apache 2.0. See [`LICENSE`](LICENSE).
