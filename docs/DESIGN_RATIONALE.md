# AMAS Design Rationale

## Why Four Tiers

The four-tier hierarchy (CANONICAL / OPERATOR / SESSION / INFERRED) reflects the actual authority structure in deployed LLM systems:

- **Tier 0 exists** because every model has behavioral boundaries that should not be overridable by any user or developer. These are constitutional.
- **Tier 1 exists** because developers configure models for specific applications. Their instructions should constrain user behavior but not override platform safety.
- **Tier 2 exists** because runtime context (user messages, tool outputs, retrieved documents) is the operational environment. It should inform behavior but not override configuration.
- **Tier 3 exists** because models generate conclusions that are qualitatively different from their inputs. An inference is not a fact. Treating them identically is how hallucination propagates.

Three tiers would conflate developer and platform authority. Five or more tiers would add resolution complexity without matching real deployment patterns. Four is the minimum that captures the actual authority relationships.

## Why Deterministic Conflict Resolution

AMAS uses deterministic rules (applied in strict order) rather than probabilistic or learned arbitration for three reasons:

1. **Auditability.** A deterministic system produces the same resolution given the same inputs. An auditor can verify that the correct rule was applied.
2. **Predictability.** Developers integrating AMAS need to know how conflicts will be resolved before they occur.
3. **Simplicity.** Five rules, applied in order, first match wins.

## Why Explicit Inference Marking

The requirement that all Tier 3 content carry `inference_marker: true` exists because the most common authority failure in LLM systems is treating model-generated conclusions as established facts.

This happens:
- within a session, when the model later reuses its own prior inferences as facts
- across agents, when one agent's inference is treated as another agent's session input

Inference marking makes epistemic status visible.

## Why External Enforcement

AMAS is designed to be enforced outside the model, not inside it.

- LLMs do not natively maintain authority graphs.
- External enforcement is auditable.
- External enforcement is model-agnostic.

The cost is middleware.
The benefit is that the model works today with existing systems.

## Why Split Governance from Runtime Binding

Earlier AMAS drafts and supporting materials mixed immutable governance doctrine with runtime bookkeeping and workflow mechanics.

That created a structural risk:
- governance rules could become entangled with implementation details
- runtime conveniences could be mistaken for constitutional rules
- conformance could become ambiguous because the spec mixed what must be true with how one runtime currently does it

The split resolves that:

- `SPEC.md` defines immutable governance doctrine
- `RUNTIME_BINDING.md` defines activation, validation, append, repair, export, and state-transition mechanics
- `CONFORMANCE_PROFILES.md` defines capability ladders and migration from legacy conformance levels

This keeps the constitutional layer small and stable while allowing runtime doctrine to evolve.

## Why Immutable Sealed Cells (AMCS)

The AMCS reference implementation uses immutable, hash-verified bundles rather than mutable databases for memory persistence.

- **Immutability prevents silent revision**
- **Hash verification prevents tampering**
- **Full-crawl prevents selective omission**

The tradeoff is storage efficiency.
Delta cells and supercell assembly provide evolution without mutation.

## Why New Core Invariants Were Added

The additional governance invariants exist to address failure surfaces that were previously implicit rather than explicit:

- **single canonical root** prevents wrapper/canonical ambiguity
- **single writable truth ledger** prevents ledger drift
- **hydrate never mutates** prevents load-time laundering or silent normalization
- **derived artifacts cannot define truth or gate reads** prevents secondary views from becoming covert authority
- **sealed memory as durable memory** prevents unsealed context from being silently treated as canon

These invariants were already directionally present in AMCS practice.
The governance split makes them explicit at the AMAS level.

## Why "Memory Object" Rather Than "Token" or "Message"

AMAS operates at the semantic level — a fact, an instruction, a constraint, a conclusion — rather than at the token or message level.

Tokens are model-internal representations with no stable semantic boundary.
Messages are too coarse.
Memory Objects match how authority actually works: a specific claim has a specific source at a specific authority level.
