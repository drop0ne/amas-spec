# AMAS Design Rationale

## Why four authority tiers

The four-tier hierarchy (CANONICAL / OPERATOR / SESSION / INFERRED) reflects distinct authority sources in deployed LLM systems:

- **Tier 0** — foundational constraints lower tiers cannot override;
- **Tier 1** — deployer/operator configuration within Tier 0;
- **Tier 2** — user/runtime context within Tiers 0–1;
- **Tier 3** — model-generated inference, qualitatively different from sourced material and lowest authority.

AMAS Core keeps this constitutional hierarchy small. Deployment-specific submodels may refine it without changing the Core relation.

## Why authority tier and semantic role are separate

Earlier AMAS 2.0 drafts placed user directives, retrieved documents, and tool data in the same Tier 2 bucket. That made **data is not instruction** a design intent rather than a machine distinction.

The Memory Object therefore carries a second independent dimension:

- `DIRECTIVE`
- `EVIDENCE`
- `OBSERVATION`
- `INFERENCE`

A retrieved document may be legitimate Tier 2 material while remaining `EVIDENCE`; a tool result may be Tier 2 `OBSERVATION`; a user message may be segmented into both a Tier 2 directive and quoted Tier 2 evidence.

This directly addresses same-tier authority laundering that tier precedence alone cannot solve.

## Why imperative wording is irrelevant

If wording determined semantic role, an attacker could create authority merely by writing system-like or command-like text.

AMAS therefore requires role to come from trusted ingestion/segmentation metadata and authorized transitions—not persuasion, capitalization, role-play language, or model interpretation.

## Why full Memory Object admission precedes arbitration

Authority logic must not inspect only the fields convenient to a comparison. Otherwise a malformed object with a privileged-looking tier could win despite violating the normative contract.

The reference therefore admits a Memory Object under its complete closed contract before it can participate in conflict arbitration. Schema invalidity fails closed rather than becoming partial authority.

## Why deterministic conflict resolution

Security-sensitive authority should be auditable, predictable, and fail closed. The ordering is:

1. semantic-role admissibility for behavioral conflicts;
2. tier precedence;
3. explicit authorized supersession;
4. structural scope specificity;
5. recency;
6. halt/escalate.

Non-directive content cannot become a candidate instruction.

## Why specificity precedes recency

Earlier drafts placed recency first. That let newly introduced generic same-tier instructions displace older task-scoped instructions.

Specificity now uses only explicit `scope_path` prefix containment. Natural-language similarity, embeddings, token count, and model confidence are not specificity evidence.

## Why Rule 5 has one outcome

Earlier language allowed either a “more restrictive interpretation” or operator escalation, producing two conforming outputs for identical inputs.

Rule 5 now has one authority result: **HALT/ESCALATE**. Presentation/recovery may vary, but the disputed mutation/action is not authorized.

## Why supersession requires external authorization

A `supersedes` field is a claim about authority, not proof of authority. If a Memory Object could authenticate its own supersession merely by naming another object and carrying self-written provenance, Rule 2 would become an authority-laundering path.

AMAS Core therefore requires the issuer to possess sufficient authority. Runtime Binding/AAB make that operational: the supersession chain must be structurally traceable and a trusted authority context outside the disputed object must confirm the issuer's authority over the superseded tier/scope.

Missing or unavailable verification fails closed. Provenance explains the claimed transition; it does not manufacture authorization.

## Why explicit inference marking

Models can recycle their own conclusions as though they were sourced facts, and multi-agent pipelines can erase inferential origin.

Tier 3 and `INFERENCE` are mutually binding. Inference cannot be a direct directive.

## Why semantic-role transition creates a new object

Changing evidence into an instruction is itself authority-bearing. Mutating `EVIDENCE` into `DIRECTIVE` would erase who made the decision.

An authorized issuer therefore creates a new directive and preserves source material in provenance.

## Why external action enforcement

AMAS/AAB does not trust the model to police its own authority graph.

External enforcement is inspectable, model-agnostic, fail-closed independent of the model's reasoning, and prevents model-generated rationale from becoming authorization.

The cost is a trusted mediation plane and authoritative security state.

## Why authorization binds the effective action

Model-declared intent can differ from the real effect after adapter resolution, redirects, parameter interpretation, credential selection, or side-effect classification.

The trusted adapter therefore prepares the effective action first. Capability-contract validation and AAB policy evaluation operate on that prepared descriptor, and its exact Canonical JSON hash is included inside the chained authorization receipt.

This prevents “authorize A, execute B” from being an acceptable reference flow.

## Why authorization and completion are separate

An external side effect can occur even when the caller never receives a successful response. The adapter may throw after the remote effect, crash, lose the response, or return a value that cannot be serialized.

Representing those cases as “execution failed” encourages unsafe retry.

The reference therefore records `STARTED` before dispatch and distinguishes:

- `SUCCEEDED` — adapter returned after dispatch;
- `OUTCOME_UNKNOWN` — dispatch occurred but the outcome cannot be established.

A recovered `STARTED` is treated as `OUTCOME_UNKNOWN`. This does not create distributed exactly-once semantics; it preserves epistemic honesty about the effect boundary.

## Why durable state is transactional

Replay, sequence, and budget state are authority. If two processes authorize from the same stale snapshot, authority can be double spent even when each individual policy evaluation is correct.

The reference uses a compact local transaction lock plus reload-before-evaluate/persist. Production systems may use stronger stores, but stale concurrent authorization is non-conformant.

## Why durable state has a bounded-epoch option

Keeping every nonce, receipt, and ancestor forever is easy to audit but unbounded in cost. Silently deleting old replay evidence is unsafe because it can restore spent authority.

`BoundedDurableEnforcementBroker` therefore uses an explicit finite event ceiling: when capacity is reached, authorization fails closed until an operator checkpoints/rotates the epoch. Production compaction is allowed only if equivalent security evidence is preserved.

## Why portable C/C++-compatible types

A security protocol should not change meaning with the implementation language. Python arbitrary integers, platform-width C `long`, `size_t`, pointer values, native `time_t`, and boolean/integer coercion can produce cross-runtime ambiguity.

The portable type profile therefore uses fixed-width C/C++-representable semantic domains. Canonical JSON security integers remain limited to `±(2^53-1)` even when stored in `int64_t`/`uint64_t`, preserving exact behavior across common JSON runtimes.

`include/amas/types.h` is compiled as C11 and C++17 in CI.

## Why split governance from runtime binding

Mixing constitutional rules with runtime bookkeeping risks turning implementation convenience into doctrine.

The split is intentional:

- `SPEC.md` — AMAS Core authority doctrine;
- `schemas/memory_object.schema.json` — normative machine representation;
- `RUNTIME_BINDING.md` — generalized activation/mutation/export and AAB seam;
- `CONFORMANCE_PROFILES.md` — capability/evidence ladders;
- `docs/AGENT_AUTHORITY_BOUNDARY.md` — external action authority;
- AMCS — reference persistence/sealing.

## Why one normative Memory Object schema

Duplicating machine schema inside prose allowed drift. The standalone schema is the sole normative machine-readable Memory Object source. Prose explains semantics but does not maintain an independently editable copy.

If prose and schema disagree, the discrepancy is a defect to repair rather than a choice between interpretations.

## Why immutable sealed cells (AMCS)

AMCS uses immutable hash-verified bundles so persistence remains reviewable. Hash consistency alone is not provenance authenticity, so higher-assurance sealing may require authenticated/externally anchored roots.

The supported reference conformance path also validates claimed generated JSON surfaces against repository schemas; a byte-consistent but schema-invalid cell is not treated as conformance success.

## Why AMCS claim boundaries are explicit

The AMCS protocol contains richer workflow semantics than the compact reference implementation automates.

The current reference can copy/bind an ODT and identify it as a primary narrative source, but it does not parse ODT document semantics into structured canonical narrative. It can verify and bundle supercell children, but it does not automate cross-cell semantic contradiction discovery or authority reconciliation.

Separating implemented mechanics from future semantic automation prevents archive functionality from being mistaken for evidence it does not provide.

## Why Memory Objects rather than tokens or messages

Tokens lack stable semantic authority boundaries. Messages are often too coarse because one message can contain directives, quotations, evidence, and inference simultaneously.

Memory Objects are semantic units whose authority and role can be represented independently. Implementations must make segmentation explicit enough for audit rather than allowing message boundaries to silently determine authority.
