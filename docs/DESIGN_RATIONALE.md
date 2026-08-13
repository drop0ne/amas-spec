# AMAS Design Rationale

## Why four authority tiers

The four-tier hierarchy (CANONICAL / OPERATOR / SESSION / INFERRED) reflects distinct authority sources in deployed LLM systems:

- **Tier 0** represents foundational constraints that lower tiers cannot override.
- **Tier 1** represents deployer/operator configuration within Tier 0.
- **Tier 2** represents user and runtime context within Tiers 0–1.
- **Tier 3** represents model-generated inference, which is qualitatively different from sourced material and carries the lowest authority.

Three tiers would conflate platform and operator authority. More tiers may be useful in deployment-specific submodels, but AMAS Core keeps the constitutional hierarchy small.

## Why authority tier and semantic role are separate

A major ambiguity in earlier AMAS 2.0 drafts was that Tier 2 included both user directives and retrieved/tool data. That allowed the phrase **data is not instruction** to exist as design intent without a machine representation.

The revised Memory Object therefore adds a second dimension:

- `DIRECTIVE`
- `EVIDENCE`
- `OBSERVATION`
- `INFERENCE`

This prevents source authority from being confused with operational meaning.

A retrieved document can be legitimate Tier 2 material while still being `EVIDENCE`, not a command surface. A tool result can be Tier 2 `OBSERVATION` even if the returned bytes contain imperative text. A user message may be segmented into both a Tier 2 `DIRECTIVE` and quoted Tier 2 `EVIDENCE`.

This distinction addresses same-tier prompt-injection/authority-laundering cases that tier precedence alone cannot resolve.

## Why imperative wording is irrelevant to semantic role

If wording could determine role, an attacker could create authority merely by writing text that resembles a system prompt or command.

AMAS therefore requires semantic role to come from trusted ingestion/segmentation metadata and authorized transitions—not persuasion, capitalization, role-play language, or model interpretation.

## Why deterministic conflict resolution

AMAS uses deterministic rules rather than probabilistic arbitration because security-sensitive authority should be:

1. **auditable** — reviewers can reconstruct why a result won;
2. **predictable** — implementations can be compared against the same vectors;
3. **fail-closed** — unresolved conflicts do not become model-selected authority.

The revised ordering is:

1. tier precedence;
2. explicit supersession;
3. explicit scope specificity;
4. recency;
5. halt/escalate.

Semantic-role admissibility occurs before directive arbitration: non-directive content cannot become a candidate instruction.

## Why specificity precedes recency

Earlier drafts placed recency before specificity. In practice that made specificity nearly unreachable and allowed newly introduced generic same-tier instructions to displace older task-scoped instructions.

The revised Rule 3 defines specificity only by explicit `scope_path` prefix containment. Natural-language similarity, embedding distance, token count, and model confidence are not specificity evidence.

This makes the ordering deterministic and prevents a generic late-arriving object from silently widening a narrower active directive.

## Why Rule 5 has only one outcome

Earlier draft language allowed either a "more restrictive interpretation" or operator escalation. That admitted two conforming outputs for identical inputs and therefore contradicted AMAS's deterministic design goal.

Rule 5 now has one result: **HALT/ESCALATE**. An implementation may have deployment-specific presentation or recovery mechanics, but the disputed mutation/action is not authorized by the unresolved conflict.

## Why explicit inference marking

Models can recycle their own conclusions as though they were sourced facts, and multi-agent pipelines can erase inferential origin as outputs are passed between agents.

AMAS therefore makes Tier 3 and `INFERENCE` mutually binding: Tier 3 must be `INFERENCE` with `inference_marker: true`, and `INFERENCE` must be Tier 3.

Inference cannot be a direct directive.

## Why semantic-role transition creates a new object

Changing evidence into an instruction is itself an authority-bearing act. Mutating an `EVIDENCE` object into a `DIRECTIVE` would erase who made that decision.

AMAS therefore requires an authorized issuer to create a new directive and preserve the source material in provenance. This keeps "data → decision" transformations visible for audit.

## Why external enforcement

AMAS is designed to be enforced outside the model rather than trusting the model to police its own authority graph.

- external enforcement is inspectable;
- it is model-agnostic;
- it can fail closed independently of the model's reasoning;
- it prevents model-generated rationale from becoming authorization.

The cost is additional middleware and trusted state. AAB defines the corresponding action-authority boundary for side-effecting agents.

## Why split governance from runtime binding

Earlier supporting materials mixed constitutional rules with runtime bookkeeping. That created a risk that implementation conveniences could be mistaken for core authority rules.

The split is intentional:

- `SPEC.md` — AMAS Core authority doctrine;
- `schemas/memory_object.schema.json` — normative machine representation of Memory Objects;
- `RUNTIME_BINDING.md` — generalized activation/mutation/export mechanics;
- `CONFORMANCE_PROFILES.md` — capability/evidence ladders;
- `docs/AGENT_AUTHORITY_BOUNDARY.md` — external action authority;
- AMCS — a reference persistence/sealing protocol.

## Why one normative Memory Object schema

Duplicating a JSON Schema inside prose and in `/schemas` allowed the two representations to drift. The standalone schema is now the sole machine-readable normative source. Prose explains its semantics but should not carry an independently editable copy.

If prose and schema disagree, the discrepancy is a defect to repair rather than an invitation for implementations to choose the weaker interpretation.

## Why immutable sealed cells (AMCS)

AMCS uses immutable, hash-verified bundles to make persistence reviewable. The design goal is to prevent silent revision and preserve provenance across selective rehydration.

Hash consistency alone is not equivalent to provenance authenticity; higher-assurance sealing may require authenticated/externally anchored roots. AMCS hardening tracks this distinction explicitly.

## Why Memory Objects rather than tokens or messages

Tokens are model-internal units without stable semantic authority boundaries. Messages are often too coarse because one message can contain commands, quotations, evidence, and inference simultaneously.

Memory Objects are semantic units whose authority and role can be represented independently. Implementations must make segmentation decisions explicit enough for audit rather than allowing message boundaries to silently determine authority.
