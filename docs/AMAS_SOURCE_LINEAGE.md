# AMAS Source Lineage and Reconciliation Record

**Integration record date:** 2026-11-22.
**Purpose:** preserve the difference between distinct AMAS expansions, their revisions, and unvalidated research.
**Operation:** additive documents/schema/tests only; no AMAS Core, AMCS, AAB or ATTICUS canonical version bump.

| Historical track | Known record | Status in this repository |
| --- | --- | --- |
| Authority Mapping and Arbitration System | AMAS v1.1 draft, April 3, 2026 | Historical predecessor; four-tier authority baseline retained, not an active spec |
| Authority Mapping and Arbitration System | AMAS v1.2 post-repair, April 4, 2026 | Historical predecessor; runtime-binding and ledger principles incorporated in successor track |
| Authority Mapping and Arbitration System | AMAS Core 2.0-draft, August 12, 2026 | **Current root normative draft** (`SPEC.md`); supersession/specificity/fail-closed rules differ from v1.1 |
| Agent Authority Boundary | AAB 0.4.1-draft | Existing normative research extension and executable reference mechanisms |
| Memory Cell Sealing | AMCS 0.3.3 reference / v1.2.1 INTERNAL protocol | Existing tested subset and documented semantic automation gaps |
| Adaptive Manipulation Analysis System | July 2026 AMAS–Symbalics architecture and manuscript Ch. 9 | **Distinct proposed technology**, summarized in `research/amas-manip/`; not an integrated detector |
| Symbalics cognition | July 2026 Mathematical Specification v0.2 | Separate proposed cognition plane, not a synonym for either AMAS |
| AMAS–Symbalics manuscript | v2.6 Pass9C and v2.7 Pass9D reviewer editions | Context only; Pass9D is later review material, not proven canonical supersession of Pass9C book |
| ATTICUS governance | v6.5.0-ABG identified in the July research record | External governance baseline; no ATTICUS engine or new ATTICUS release is committed here |
| AMAS Publication Program | separate v3.0.0 paper/archive track identified in November historical notes | Separate version series; not a replacement for Core 2.0 or the book |

## Explicit reconciliation

- **Known**: both historical AMAS expansions exist and are substantively different. The short labels **AMAS-AUTH** and **AMAS-MANIP**, and the "AMAS Integrity Plane" umbrella, appeared as a *proposed* July naming resolution.
- **Selected for repo clarity**: use these qualified labels in newly authored public documentation, without silently rewriting existing Core identifiers or asserting a newly ratified canonical release.
- **Known**: Core reference code and its tests cover selected AAB/AMCS mechanisms. No evidence establishes deployed A4 containment.
- **Unknown**: final patent/publication disposition; formal ratification of the umbrella naming; definitive authorial supersession of Pass9C by Pass9D; full source archive hashes accessible in this GitHub audit; integrated manipulation detector performance.
- **Disclosure rule**: identify source version and maturity; do not copy the full unpublished reviewer manuscript or private development archives into a public branch without separate reviewed release authorization.
- **License**: this repository's current `LICENSE` is **All Rights Reserved**. Historical v1.1 Apache 2.0 markings are revision-specific and do not override the current file's terms. No conclusion is made about retroactive licensing of earlier versions.

## Change control

Future work proposing **normative** manipulation-analysis requirements must separately version AMAS-MANIP, specify implementations and tests, record security/evidence limits, and obtain operator approval. Changes to AMAS-AUTH remain governed by its own normative specification and conformance profiles; there is no implied cross-track supersession.

