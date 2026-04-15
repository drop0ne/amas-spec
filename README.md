# AMAS — Authority Mapping and Arbitration System

**A formal governance model for memory authority in Large Language Models.**

Version: 2.0-draft  
Status: Open for review  
Author: Jacob Dougherty  
License: Apache 2.0

---

## The Problem

Large Language Models have no concept of epistemic authority.

When an LLM processes a conversation, it receives input from multiple sources: system instructions from the platform, configuration from the developer, messages from the user, results from tools, retrieved documents, and its own prior outputs. All of these compete for influence over the model's behavior — but the model has no formal mechanism for deciding which source should prevail when they conflict.

This creates three categories of failure:

**Prompt injection.** A user message or retrieved document overrides system-level safety instructions because the model cannot distinguish between authority tiers.

**Authority laundering.** An automated system makes consequential decisions, but because the decision was produced by an AI model acting on ambiguous instructions, no party is clearly accountable. The authority to decide was never formally delegated — it was laundered through the model's context window.

**Memory drift.** Across sessions, AI systems accumulate context from prior interactions, retrieved data, and inferred patterns. Without a formal hierarchy, an inference from three sessions ago can silently override an explicit instruction from the current operator.

Every major LLM provider has ad-hoc mitigations for some of these problems — role-based message channels, instruction hierarchies, safety layers. None has a formal, auditable, deterministic model for how authority flows through the context window.

AMAS provides that model.

---

## What AMAS Defines

### Governance Core

AMAS establishes four tiers of memory authority, ordered by precedence:

| Tier | Name | Description |
|------|------|-------------|
| 0 | **CANONICAL** | Foundational rules, safety constraints, and system invariants. Immutable within a version. Cannot be overridden by any lower tier. |
| 1 | **OPERATOR** | Developer or deployer instructions. Configures behavior within the boundaries set by Tier 0. |
| 2 | **SESSION** | User messages, conversation history, uploaded documents, tool outputs. The runtime context of a single interaction. |
| 3 | **INFERRED** | Conclusions drawn by the model from available context. Must be explicitly marked as inference. Lowest authority; never overrides any other tier. |

The AMAS governance core also defines immutable invariants for:
- single canonical root resolution
- single writable truth-ledger discipline
- explicit memory activation
- hydrate immutability
- provenance-gated activation
- derived-artifact truth and read boundaries
- repair and export discipline
- sealed-memory durability

### Conflict Resolution Protocol

When memory sources conflict, AMAS applies five deterministic rules in order:

1. **Tier precedence.** Higher tier always prevails over lower tier. No exceptions.
2. **Explicit supersession.** Within the same tier, a source that explicitly replaces a prior source prevails, provided the replacement is authorized and traceable.
3. **Recency.** Within the same tier, absent explicit supersession, the most recent source prevails.
4. **Specificity.** Within the same tier, same recency, the more specific source prevails over the more general.
5. **Conservative default.** If no rule resolves the conflict, the system defaults to the more restrictive interpretation or flags the conflict for operator resolution.

### Memory Object Schema

Every item in the authority hierarchy is a **Memory Object** — a discrete, self-contained unit of information with attached metadata.

AMAS continues to define the Memory Object model in `SPEC.md`. Runtime mechanics that operate on Memory Objects now live in `RUNTIME_BINDING.md`.

### Runtime Binding and Conformance

AMAS governance doctrine is distinct from runtime mechanics.

- `SPEC.md` defines the immutable governance core
- `RUNTIME_BINDING.md` defines activation, validation, append, repair, export, and state-transition mechanics
- `CONFORMANCE_PROFILES.md` defines capability ladders and the migration path from the legacy Level 1–3 model

This split prevents governance doctrine from being silently reshaped by runtime bookkeeping details.

---

## Why This Matters

### For AI Safety

AMAS provides a formal model for prompt injection resistance. If a retrieved document (Tier 2) contains instructions that conflict with system safety constraints (Tier 0), the conflict resolution protocol deterministically rejects the override. No heuristics, no judgment calls — the tier hierarchy is the arbitration mechanism.

### For Accountability

The concept of **automated authority laundering** describes a failure mode where AI systems make consequential decisions without clear authority delegation. AMAS addresses this by requiring every Memory Object to carry provenance metadata — who created it, at what tier, through what chain of authority. Decisions made through the model's context window become traceable to their authoritative source.

See [docs/AUTHORITY_LAUNDERING.md](docs/AUTHORITY_LAUNDERING.md) for a detailed treatment of this concept.

### For Multi-Agent Systems

As AI systems increasingly operate in multi-agent architectures — where models delegate to other models, spawn sub-tasks, and aggregate results — the authority problem compounds. AMAS provides the governance layer that prevents authority from being silently escalated or diluted across agent boundaries.

---

## Conformance Profiles

AMAS v1.1 exposed three inline conformance levels. The repository is now transitioning toward a separated capability-ladder model.

- Legacy inline Levels 1–3 remain summarized in `SPEC.md`
- Forward-looking capability definitions and migration guidance live in `CONFORMANCE_PROFILES.md`

This preserves continuity for existing readers while allowing the conformance doctrine to evolve independently from the governance core.

---

## Reference Implementation

This repository includes **AMCS** (Atticus Memory Cell Sealing Protocol) — a working reference implementation in Python that demonstrates AMAS principles through memory cell sealing, integrity verification, and provenance tracking.

AMCS is a **reference runtime / sealing protocol** operating under AMAS governance. It is not the AMAS governance core itself.

```bash
# Seal a conversation into an immutable, hash-verified memory cell
python3 reference/amcs.py seal --input examples/chat_minimal.json \
    --out-dir out --cell-name DEMO_CELL

# Verify cell integrity
python3 reference/amcs.py verify --cell out/DEMO_CELL.tar.gz

# Assemble multiple cells into a supercell
python3 reference/amcs.py assemble-supercell \
    --cells out/CELL_A.tar.gz out/CELL_B.tar.gz \
    --out-dir out --supercell-name COMBINED --scope "project_scope"
```

See [reference/README.md](reference/README.md) for runtime documentation.

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
├── spec/
│   └── AMCS_v1.2.1.md
├── reference/
│   ├── amcs.py
│   └── README.md
├── schemas/
│   ├── memory_object.schema.json
│   ├── common.schema.json
│   ├── seal_receipt.schema.json
│   ├── prompt_log.schema.json
│   ├── prompt_response_map.schema.json
│   ├── case_study_map.schema.json
│   ├── cell_index.schema.json
│   ├── supercell_manifest.schema.json
│   └── machine_semantic_links.row.schema.json
├── templates/
│   └── operator_command_template.txt
├── examples/
│   ├── conflict_tier_precedence.json
│   ├── conflict_injection_attempt.json
│   ├── conflict_same_tier.json
│   ├── chat_minimal.json
│   └── chat_minimal.txt
└── docs/
    ├── AUTHORITY_LAUNDERING.md
    ├── THREAT_MODEL.md
    └── DESIGN_RATIONALE.md
```

---

## Prior Art and Relationship to Existing Work

AMAS draws on concepts from established fields while defining a novel governance model specific to AI memory:

- **Role-based access control (RBAC)** in operating system security — for tier precedence design.
- **OAuth 2.0** (RFC 6749) — for authority delegation patterns.
- **POSIX filesystem permission hierarchies** — for layered precedence models.
- **Prompt injection research** (Greshake et al., 2023; Perez & Ribeiro, 2022) — for threat model analysis.

AMAS is distinct from these in that it addresses memory authority in AI systems specifically — a problem space where no prior formal specification exists.

---

## Status and Roadmap

- [x] AMAS v1.1 specification (complete)
- [x] AMCS reference implementation (working, v0.1.1)
- [x] JSON schemas for Memory Objects and sealed cells
- [x] Governance/core vs runtime-binding doctrinal split (draft)
- [x] Conformance-profile extraction with migration path (draft)
- [ ] Conformance test suite
- [ ] Prompt injection resistance benchmark
- [ ] arXiv preprint
- [ ] Multi-agent authority negotiation extension

---

## Citation

If referencing this work:

```text
Dougherty, J. (2026). AMAS: Authority Mapping and Arbitration System
for Memory Governance in Large Language Models. Draft specification.
https://github.com/[repo-url]
```

---

## License

Apache 2.0. See [LICENSE](LICENSE).
