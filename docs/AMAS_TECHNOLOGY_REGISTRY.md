# AMAS Technology Registry — Two Distinct Expansions

**Status:** naming clarification / research crosswalk (2026-11-22). This registry does not amend the normative AMAS Core specification or represent approval of unvalidated research mechanisms.

The historical research program uses **AMAS** for two *different technologies*. A bare "AMAS" is ambiguous outside its historical context. Use the qualified names below for all new cross-project work.

| Public namespace | Full technology name | Distinct purpose | Location / maturity |
| --- | --- | --- | --- |
| **AMAS-AUTH** | **Authority Mapping and Arbitration System** | Classifies authority and semantic roles; arbitrates conflicts and protects canonical state; connects to AMCS persistence and AAB action enforcement | Root `SPEC.md`, `RUNTIME_BINDING.md`, `CONFORMANCE_PROFILES.md`; Core 2.0-draft plus reference implementations |
| **AMAS-MANIP** | **Adaptive Manipulation Analysis System** | Investigates manipulation- and frame-capture *indicators* affecting input, memory, cognition, and action proposals; preserves uncertainty, alternative explanations, and correction | `research/amas-manip/`; conceptual research, no validated detector or runtime |
| **AMAS Integrity Plane** | Working umbrella name, **not a third AMAS expansion** | Proposed interface coordinating AMAS-AUTH decisions and AMAS-MANIP annotations under external state/action control | `docs/AMAS_INTEGRATION_CONTRACT.md`; proposed |
| **Symbalics** | Multi-timescale, symbolically modulated cognition research architecture, **not an AMAS acronym expansion** | Candidate symbolic state, recurrent workspace, memory, correction, neural-symbolic interfaces | `research/symbalics/`; theoretical, unvalidated |
| **ATTICUS** | Governance/operating framework, **not a synonym for AMAS** | Policy, evidence discipline, bounded reasoning, safety, OPSEC and operational workflow | External canonical framework; the integration does not declare an ATTICUS release |

## Important boundaries

1. **Existing root AMAS = AMAS-AUTH.** All established Core 2.0 normative `MUST` requirements, AAB and AMCS reference code, conformance levels and existing schema contracts retain their current meaning. The namespace tag is descriptive; no silent version or specification supersession is implied.
2. **AMAS-MANIP is not an authorization service.** A manipulation annotation, flag, inferred intent, or model confidence can never create or elevate a `DIRECTIVE`, Memory Object authority tier, capability lease, permission, or action authorization.
3. **Different evidence types:** AMAS-AUTH reference tests establish only their declared implementation properties. AMAS-MANIP detectors, calibrated scores, and Symbalics runtime gains are not claimed implemented or empirically established here.
4. **No inferred attacker intent:** emotional language, repetition, dissent, unusual statements, advocacy, or distress do not by themselves establish manipulation, malice, or falsehood.
5. **Independent versions:** Core 2.0-draft, AAB 0.4.1-draft, AMCS 0.3.3/v1.2.1 INTERNAL, AMAS-MANIP research draft, and the separate Symbalics manuscript track must never be treated as one versioned release.
6. **No change to ATTICUS authority:** ATTICUS v6.5.0-ABG is the identified historical/current manuscript baseline; incorporation here neither implements ATTICUS nor asserts control over platform runtime policy.
7. **Disclosure:** the complete unpublished research manuscripts, internal files, personal conversations, implementation-sensitive appendices, and private evidence packages are not incorporated into this public repository by this change.

## Navigation

- `research/amas-manip/RESEARCH_SPEC.md` — proposed manipulation-analysis requirements and nonclaims
- `schemas/manipulation_signal.schema.json` — experimental non-authorizing observation format
- `docs/AMAS_INTEGRATION_CONTRACT.md` — proposed AMAS-AUTH / AMAS-MANIP / Symbalics seam
- `research/symbalics/ARCHITECTURE.md` — architecture overview, without a claim of implementation
- `research/symbalics/EVALUATION.md` — falsifiable H1–H6 research hypotheses
- `docs/AMAS_SOURCE_LINEAGE.md` — evidence, chronology, scope and release boundaries

