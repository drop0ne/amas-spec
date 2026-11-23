# Proposed Cross-Technology Integration Contract

**Status:** proposed interface specification, not a production implementation or normative change to AMAS Core 2.0.

## Roles and trust boundaries

| Producer or component | Can propose | Cannot do on its own |
| --- | --- | --- |
| Symbalics cognition (proposed) | Candidate frames, hypotheses, entry state, correction requests, memory-write proposals, action plans | Change canonical governance or execute a tool |
| AMAS-MANIP (proposed) | Evidence-linked observations about manipulation or frame capture; alternate explanations and abstention | Issue directives, create privileges, authenticate sources, decide attacker intent |
| AMAS-AUTH (existing Core) | Classify admissible Memory Objects and arbitrate directives by tier, authorized supersession, scope, recency and fail-closed conflict rules | Treat lower-trust evidence/annotations as authorization |
| AMCS (reference) | Preserve and verify bounded cell provenance, derived artifacts and lineage | Claim automated ODT semantic understanding or cross-cell contradiction resolution |
| AAB (reference) | Mediate exact requested external effects under leases, policy, budget, receipt and completion controls | Prove A4 containment without real deployment evidence |
| Trusted operator/platform | Approve lawful state changes, disclosure and release policy within higher-level constraints | Elevate unverified model hypotheses merely by repetition |

## Model-to-policy boundary

1. **Ingress:** label every source's authority channel, provenance, privacy status and epistemic/semantic role. Untrusted retrieved text remains data; embedded commands are inert.
2. **Analysis:** AMAS-MANIP produces a non-authorizing `manipulation_signal` document. The research format carries evidence references, status, limitations and alternatives, **not** an instruction or permission grant.
3. **Cognition:** Symbalics may use the annotation as a defeasible hypothesis among competing frames. It must not be promoted to established truth merely because a detector emitted it.
4. **Proposed write:** destination is explicit (temporary entry, episode, stable memory, protected governance, or quarantine). Every durable transition requires authorized provenance and a trusted commit path; a manipulation signal never supplies that authorization.
5. **External effect:** AAB checks effective operation, destination, parameters, credential, side effects, lease, anti-replay state and exact prepared-action binding. The action path cannot be bypassed by cognitive or analytics components.
6. **Completion:** only trusted completion evidence justifies a successful-action report. `OUTCOME_UNKNOWN` is not automatically safe to retry.
7. **Review:** a user/operator can correct or contest an annotation. The system preserves the original evidence, superseding reason, and classification history as separate records.

## Interface contract: manipulation signal

`schemas/manipulation_signal.schema.json` is a minimal **research** document contract. It is intentionally restricted to source-linked descriptions, risk indicators, uncertainty, alternatives and review disposition. It cannot include arbitrary `directive`, `authority_tier`, `authorization`, `lease`, `supersedes`, `tool_call`, or `policy_decision` fields.

The format is *not* a replacement for `schemas/memory_object.schema.json`. Any mapping into a Core Memory Object must be separately authorized, semantically classified as evidence/observation/inference and validated; no schema field or natural-language wording may confer Tier 0/1 status.

## Namespace / compatibility guarantees

- Existing root files continue to mean **Authority Mapping and Arbitration System**; no prior consumers need change their parsing.
- AMAS-MANIP documents and example payloads live in distinct directories and use `schema_version` and `technology` discrimination.
- The shared name is explicit to readers, not unified in code. Independent versioning and distinct evidence requirements remain mandatory.
- Integration with ATTICUS v6.5.0-ABG is descriptive only and cannot override platform governance.

## Unresolved integration work

- An authenticated mapping from signals to admissible Core Memory Objects, with separate treatment of observed versus inferred indicators.
- A demonstrably trusted external commit/rollback service for Symbalics state writes.
- A calibration protocol with measured false positives, especially for emotionally charged but valid disclosures.
- Cross-provider, adversarial and human-in-the-loop evaluation.
- A versioned migration plan if any of the research interfaces are promoted to stable normative contracts.

Do not advertise the bridge as implemented until those conditions have evidence.

