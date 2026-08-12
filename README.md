# AMAS — Authority Mapping and Arbitration System

**A formal governance model for contextual authority, memory authority, and bounded agent action.**

AMAS Core version: **2.0-draft**  
AAB extension version: **0.3-draft**  
Status: Open for review  
Author: Jacob Dougherty  
License: Apache 2.0

---

## Why AMAS Exists

Large Language Models receive instructions, data, memories, retrieved documents, tool results, and model-generated inferences through the same operational context. Tool-using agents add a second problem: a model may discover that it *can* perform an action and incorrectly treat that capability as permission.

AMAS separates:

- data from instruction
- inference from fact
- reachability from permission
- capability from authority
- successful execution from permission to broaden scope

The repository contains two complementary control planes:

1. **AMAS Core** — determines which contextual source is authoritative.
2. **AAB (Agent Authority Boundary)** — determines whether a proposed external action is authorized and whether the enforcement state used to decide that question is trustworthy.

> **No lower-authority source, model-generated inference, newly discovered capability, or successful action may silently acquire greater authority.**

---

## AMAS Core: Context and Memory Authority

AMAS defines four contextual authority tiers:

| Tier | Name | Description |
|---|---|---|
| 0 | **CANONICAL** | Foundational rules, safety constraints, and system invariants. |
| 1 | **OPERATOR** | Developer/deployer instructions and configuration. |
| 2 | **SESSION** | User messages, retrieved content, tool outputs, uploads, and runtime context. |
| 3 | **INFERRED** | Model-derived conclusions and speculation. Lowest authority. |

Conflicts are resolved through:

1. tier precedence
2. explicit supersession
3. recency
4. specificity
5. conservative default / operator resolution

AMAS Core also defines canonical-root uniqueness, a single writable truth ledger, explicit memory activation, provenance-gated hydration, append/repair discipline, export receipts, and sealed-memory durability.

See [`SPEC.md`](SPEC.md), [`RUNTIME_BINDING.md`](RUNTIME_BINDING.md), and [`CONFORMANCE_PROFILES.md`](CONFORMANCE_PROFILES.md).

---

## AAB: Agent Authority Boundary

AAB extends AMAS from memory/context governance to external action control.

AAB requires an enforcement plane outside the acting model:

```text
MODEL / AGENT
      |
      v
Structured Action Request
      |
      v
+-----------------------------+
| AMAS AAB ENFORCEMENT BROKER |
| signed lease                |
| replay state                |
| trusted usage counters      |
| policy gate                 |
| receipt chain               |
+-----------------------------+
      |
 ALLOW / DENY / ESCALATE
      |
      v
 Tool Adapter / Side Effect
```

### Core AAB invariants

- Capability is not authority.
- Reachability is not authorization.
- Data is not instruction.
- Inference is not delegation.
- Success does not widen scope.
- No ambient credentials or privileges.
- Delegation may narrow but never silently broaden.
- Missing, expired, stale, replayed, or unverifiable authority fails closed.
- The model is not the sole judge of its own authority.
- Enforcement-critical counters are broker-owned, not agent-owned.
- Every authorization decision is auditable.
- Higher containment claims require evidence, not assertion.

See [`docs/AGENT_AUTHORITY_BOUNDARY.md`](docs/AGENT_AUTHORITY_BOUNDARY.md).

---

## Reference Implementations

### Policy gate

`reference/authority_gate.py` evaluates structured requests against an explicit authority policy. It never executes requested actions.

It demonstrates:

- deny-by-default allowlists
- objective/operation/target scope
- destination/network scope
- credential scope
- side-effect ceilings
- expiring policies
- action/network/egress/time budgets
- delegation-depth limits
- operator escalation
- policy/request receipt hashes

### Monotonic delegation

`reference/delegation.py` verifies that child authority is a subset of parent authority across objectives, operations, targets, destinations, credentials, side-effect ceilings, budgets, expiration, and delegation depth.

### Receipt chaining

`reference/receipt_chain.py` creates and verifies SHA-256-linked authorization receipts. It detects mutation and reordering within an observed chain. Production deployments should independently anchor chain tips to address truncation risk.

### Enforcement broker — AAB 0.3

`reference/enforcement_broker.py` adds enforcement-path state that the acting model cannot self-report:

- authenticated/signed authority leases
- lease binding
- nonce replay detection
- monotonic request sequences
- request freshness checks
- broker-owned cumulative usage counters
- broker-bound action cost
- chained decision receipts

The reference uses HMAC-SHA256 for compact demonstration. Production systems should keep signing authority outside the model environment and use deployment-appropriate workload identity or key management.

Run the existing policy-gate demonstration:

```bash
python3 reference/authority_gate.py \
  --policy examples/authority_policy.json \
  --requests examples/action_requests.json
```

Run all tests:

```bash
python3 -m unittest discover -s tests -v
```

---

## Adversarial Evidence

`adversarial/aab_vectors.json` contains reproducible policy-level containment vectors including:

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
- exact-boundary cases

AAB 0.3 additionally tests enforcement-path attacks including signed-lease tampering, nonce replay, request-sequence gaps, stale/future requests, agent attempts to spoof cumulative usage, broker-budget exhaustion, and receipt mutation.

These tests validate the reference controls under the tested assumptions. They do **not** establish that a frontier model cannot bypass an entire deployed containment architecture.

---

## AMCS Memory Runtime

This repository also includes **AMCS (Atticus Memory Cell Sealing Protocol)**, a reference persistence/sealing runtime operating under AMAS governance.

```bash
python3 reference/amcs.py seal \
  --input examples/chat_minimal.json \
  --out-dir out \
  --cell-name DEMO_CELL

python3 reference/amcs.py verify --cell out/DEMO_CELL.tar.gz
```

- **AMCS** addresses memory provenance, sealing, integrity, and rehydration.
- **AAB** addresses authorization of proposed side effects and integrity of the authorization path.

---

## Conformance

AMAS uses independent capability axes.

### Memory/runtime axis

- `C1` — read-only hydrate
- `C2` — hydrate + validate
- `C3` — append-capable
- `C4` — persistent-runtime full conformance

### Action-boundary axis

- `A0` — no action-boundary claim
- `A1` — observe/simulate boundary
- `A2` — scoped side effects
- `A3` — bounded delegation
- `A4` — adversarial containment evidence profile

Example declaration:

```text
AMAS conformance: C3/A2
```

A4 is evidence-bearing. Documentation alone is insufficient.

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
│   ├── delegation.py
│   ├── enforcement_broker.py
│   └── receipt_chain.py
├── schemas/
│   ├── memory_object.schema.json
│   ├── authority_policy.schema.json
│   ├── signed_authority_lease.schema.json
│   ├── action_request.schema.json
│   ├── broker_action_request.schema.json
│   ├── child_authority_policy.schema.json
│   └── decision_receipt.schema.json
├── adversarial/
│   └── aab_vectors.json
├── examples/
├── tests/
└── .github/workflows/
    └── ci.yml
```

---

## Threat Model

AMAS/AAB is designed to address or constrain:

- prompt injection / tier impersonation
- inference-to-authority promotion
- provenance opacity
- canonical-memory ambiguity
- silent mutation/repair
- target and destination scope creep
- ambient credential use
- privilege expansion
- budget/rate expansion or reset
- unauthorized delegation
- action laundering through tool-using agents
- signed-lease tampering
- stale/replayed requests
- agent-supplied false cumulative usage

AMAS does not replace infrastructure security. If the enforcement plane is bypassed or compromised, AMAS cannot reconstruct the lost boundary after the fact.

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

---

## Status and Roadmap

Present in the repository:

- [x] AMAS specification lineage and 2.0-draft governance/runtime split
- [x] AMCS reference sealing runtime
- [x] Memory Object and runtime schemas
- [x] AAB action-authority architecture
- [x] executable deny-by-default policy gate
- [x] monotonic delegation verifier/deriver
- [x] tamper-evident decision receipt chain
- [x] adversarial policy vector corpus
- [x] signed authority lease reference mechanism
- [x] replay-resistant enforcement broker
- [x] broker-owned cumulative usage accounting
- [x] automated unit/conformance tests and CI

Next:

- [ ] durable external nonce/sequence state across broker restarts
- [ ] independent receipt-chain anchoring / signed checkpoints
- [ ] machine-validated JSON Schema conformance suite
- [ ] deterministic Rule 4 specificity vectors
- [ ] prompt-injection resistance benchmark
- [ ] multi-agent authority negotiation protocol
- [ ] provider/tool adapters that force all side effects through the broker
- [ ] adversarial enforcement-path bypass harness
- [ ] independent external evaluation
- [ ] preprint/publication package

---

## Design Position

AMAS is not a claim that a language model can be made trustworthy by instruction alone.

The design assumes a capable model may misunderstand, overgeneralize, optimize around an evaluator, follow malicious retrieved instructions, discover unanticipated capabilities, or inaccurately represent its own state.

The defensive authority boundary therefore belongs **outside the model**.

---

## Citation

```text
Dougherty, J. (2026). AMAS: Authority Mapping and Arbitration System.
Draft specification and reference architecture.
```

## License

Apache 2.0. See [`LICENSE`](LICENSE).
