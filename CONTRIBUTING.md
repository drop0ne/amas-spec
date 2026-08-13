# Contributing to AMAS

AMAS/AAB/AMCS are security-oriented research drafts. Contributions should reduce ambiguity, improve reproducibility, or strengthen evidence without overstating what the repository proves.

## Specification feedback

High-value contributions include:

- ambiguities that could cause two conforming implementations to behave differently;
- counterexamples to authority-tier, semantic-role, scope, or delegation rules;
- adversarial cases that expose fail-open behavior;
- schema/runtime mismatches;
- missing trust assumptions or equivalent-effect paths;
- prior art relevant to authority governance, capability security, agent mediation, provenance, or containment.

## Implementation reports

When reporting an implementation of any portion of AMAS, identify:

- the exact repository/specification revision;
- claimed C-axis and A-axis profile, if any;
- mechanisms actually implemented;
- tests/evidence actually reproduced;
- assumptions and known gaps.

Do not describe a reference implementation, passing unit suite, or policy prompt as production certification or A4 containment evidence.

## Code contributions

Reference code under `reference/` accepts security fixes, conformance improvements, tests, and implementation work consistent with the normative documents.

Changes that alter serialized/sealed formats, authority semantics, state versions, or compatibility with existing artifacts must be explicit and accompanied by:

- version/migration notes;
- affected schemas;
- tests covering the old/new boundary where applicable;
- updated security/evidence documentation.

Security-sensitive changes should add adversarial tests when practical.

## Pull-request expectations

A PR should:

1. state the property it changes;
2. identify whether the change is normative, implementation-only, schema-only, or evidence-only;
3. include tests for material behavior changes;
4. keep specification, schema, runtime, and documentation synchronized;
5. pass the `conformance` workflow;
6. avoid claims stronger than the supplied evidence.

## Security reports

Do not publish a reproducible vulnerability or sensitive exploit path in a public issue. Follow `SECURITY.md`.

## What this project does not want

- marketing language that overstates containment/security evidence;
- weakening a HARD/normative rule without threat-model justification;
- model-selected or implicit authority transitions;
- hidden compatibility breaks;
- new ambient privileges, credentials, destinations, or side-effect paths;
- tests that merely duplicate implementation behavior without checking the intended invariant.

## Review principle

Be precise. Distinguish specification, implementation, test evidence, deployment evidence, and certification. Disagree with reproducible evidence.
