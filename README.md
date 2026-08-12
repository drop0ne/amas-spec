# AMAS — Authority Mapping and Arbitration System

**A formal governance model for contextual authority, memory authority, and bounded agent action.**

AMAS Core version: **2.0-draft**  
AAB extension version: **0.1-draft**  
Status: Open for review  
Author: Jacob Dougherty  
License: Apache 2.0

---

## Why AMAS Exists

Large Language Models receive instructions, data, memories, retrieved documents, tool results, and model-generated inferences through the same operational context. Without a formal authority model, systems can confuse:

- data with instruction
- inference with fact
- reachability with permission
- capability with authority
- successful execution with permission to broaden scope

AMAS separates those concepts.

The repository now has two complementary control planes:

1. **AMAS Core** — determines which contextual source is authoritative.
2. **AAB (Agent Authority Boundary)** — determines whether a proposed real-world action is authorized.

The core design goal is simple:

> **No lower-authority source and no model-generated inference may silently acquire greater authority merely because the model can act on it.**

---

## AMAS Core: Context and Memory Authority

AMAS establishes four tiers of authority:

| Tier | Name | Description |
|---|---|---|
| 0 | **CANONICAL** | Foundational rules, safety constraints, and system invariants. |
| 1 | **OPERATOR** | Developer/deployer instructions and configuration. |
| 2 | **SESSION** | User messages, retrieved content, tool outputs, uploaded material, runtime context. |
| 3 | **INFERRED** | Model-derived conclusions and speculation. Lowest authority. |

Conflicts are resolved using a deterministic precedence model:

1. tier precedence
2. explicit supersession
3. recency
4. specificity
5. conservative default / operator resolution

AMAS Core also defines invariants for canonical-root uniqueness, a single writable truth ledger, explicit memory activation, provenance-gated hydration, append/repair discipline, export receipts, and sealed-memory durability.

See [`SPEC.md`](SPEC.md).

---

## AAB: Agent Authority Boundary

The **Agent Authority Boundary** extends AMAS from memory/context governance to external action control.

AAB treats these as separate:

- **capability**
- **reachability**
- **instruction**
- **authorization**

A model may be capable of reaching a network service, using a credential, modifying a file, invoking a tool, or spawning another agent without being authorized to do so.

AAB therefore requires an external enforcement plane between the model and side effects.

```text
MODEL / AGENT
      |
      v
Action Request
      |
      v
+-----------------------+
| AMAS AAB POLICY GATE  |
| external to the model |
+-----------------------+
      |
 ALLOW / DENY
 ESCALATE / SIMULATE
      |
      v
 Tool / Network / System
```

### AAB invariants

- Capability is not authority.
- Reachability is not authorization.
- Data is not instruction.
- Inference is not delegation.
- Success does not widen scope.
- No ambient authority.
- Delegation may narrow, never silently broaden.
- Missing or expired authority fails closed.
- The model is not the sole judge of its own authority.
- Every decision produces an auditable receipt.

See [`docs/AGENT_AUTHORITY_BOUNDARY.md`](docs/AGENT_AUTHORITY_BOUNDARY.md).

---

## Reference Enforcement Gate

`reference/authority_gate.py` is a small, standard-library-only reference implementation of the AAB decision layer.

It does **not** execute actions. It evaluates proposed actions against an explicit authority lease.

It currently demonstrates:

- deny-by-default allowlists
- objective/operation/target scope
- destination/network scope
- credential scope
- side-effect ceilings
- expiring policy leases
- action/network/egress/time budgets
- delegation-depth limits
- explicit operator escalation
- SHA-256 policy/request receipt hashes

Run the demonstration:

```bash
python3 reference/authority_gate.py \
  --policy examples/authority_policy.json \
  --requests examples/action_requests.json
```

Run the conformance tests:

```bash
python3 -m unittest discover -s tests -v
```

The reference code is intentionally small enough to audit. Production deployments still require independent sandboxing, egress controls, least-privilege identities, secret isolation, rate limits, and immutable logging.

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

AMCS and AAB solve different enforcement problems:

- **AMCS** — memory provenance, sealing, integrity, rehydration.
- **AAB** — authorization of proposed side effects.

Both operate beneath AMAS governance.

---

## Conformance

Conformance is split into independent capability axes.

### Memory/runtime profiles

- `C1` — read-only hydrate
- `C2` — hydrate + validate
- `C3` — append-capable
- `C4` — persistent-runtime full conformance

### Action-boundary profiles

- `A1` — observe/simulate only
- `A2` — scoped side-effect authority
- `A3` — bounded delegation
- `A4` — adversarial containment profile

An implementation may declare both axes, for example:

```text
AMAS conformance: C3 / A2
```

See [`CONFORMANCE_PROFILES.md`](CONFORMANCE_PROFILES.md).

---

## Repository Structure

```text
amas-spec/
├── README.md
├── SPEC.md
├── RUNTIME_BINDING.md
├── CONFORMANCE_PROFILES.md
├── LICENSE
├── CONTRIBUTING.md
├── docs/
│   ├── AGENT_AUTHORITY_BOUNDARY.md
│   ├── AUTHORITY_LAUNDERING.md
│   ├── THREAT_MODEL.md
│   └── DESIGN_RATIONALE.md
├── reference/
│   ├── amcs.py
│   ├── authority_gate.py
│   └── README.md
├── schemas/
│   ├── memory_object.schema.json
│   ├── authority_policy.schema.json
│   ├── action_request.schema.json
│   ├── decision_receipt.schema.json
│   └── ...
├── examples/
│   ├── authority_policy.json
│   ├── action_requests.json
│   ├── conflict_tier_precedence.json
│   └── ...
├── tests/
│   └── test_authority_gate.py
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
- budget/rate expansion
- unauthorized delegation
- action laundering through tool-using agents

It does not claim to replace infrastructure security. If the enforcement plane itself is bypassed or compromised, AMAS cannot restore the lost boundary.

See [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

---

## Status and Roadmap

Completed or present in this repository:

- [x] AMAS v1.1 specification lineage
- [x] AMAS 2.0-draft governance/runtime split
- [x] AMCS reference sealing runtime
- [x] JSON schemas for memory artifacts
- [x] AAB 0.1-draft action-authority extension
- [x] AAB JSON schemas
- [x] executable AAB policy gate
- [x] action-boundary unit/conformance tests
- [x] CI for reference code and JSON parse validation

Next:

- [ ] machine-validated JSON Schema conformance suite
- [ ] deterministic Rule 4 specificity vectors
- [ ] policy derivation / monotonic child-policy verifier
- [ ] adversarial containment replay corpus
- [ ] prompt-injection resistance benchmark
- [ ] multi-agent authority negotiation protocol
- [ ] signed/append-only decision receipt ledger
- [ ] model/provider adapters
- [ ] independent external evaluation
- [ ] preprint/publication package

---

## Design Position

AMAS is not a claim that a language model can be made trustworthy by instruction alone.

The design assumes the opposite: a capable model may misunderstand, overgeneralize, optimize around an evaluator, follow malicious retrieved instructions, or discover capabilities that were not anticipated.

The defensive boundary therefore belongs **outside the model**.

---

## Citation

```text
Dougherty, J. (2026). AMAS: Authority Mapping and Arbitration System.
Draft specification and reference architecture.
```

---

## License

Apache 2.0. See [`LICENSE`](LICENSE).
