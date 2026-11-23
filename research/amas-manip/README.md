# AMAS-MANIP — Adaptive Manipulation Analysis System

**Technology:** distinct from AMAS-AUTH (Authority Mapping and Arbitration System).
**Maturity:** research proposal only; no production detector, no validated risk score, no deployed security boundary.
**Authority:** advisory observations only; AMAS-AUTH and independently trusted policy/action gateways retain decision authority.

AMAS-MANIP is a proposed cognitive-integrity subsystem. Its job is to identify *observable patterns that warrant examination*, not to attribute intent, infer mental state from appearance, censor emotional expression, or authorize autonomous action.

The proposed scope covers: provenance weakness, instruction/authority spoofing, repetition pressure without supporting evidence, identity overwrite, epistemic drift, attention/frame capture, privacy pressure, urgent action pressure, affiliation pressure, burden reversal, false dilemmas, selective literalism, and procedural capture. Ordinary rhetoric and emotional testimony are possible benign alternatives.

The four observational placements are: (1) input/source inspection, (2) state-write review, (3) recurrent cognition/process monitoring, and (4) pre-output/action proposal review. These are research *placements*, not implemented hooks in this repository.

See `RESEARCH_SPEC.md`, `docs/AMAS_INTEGRATION_CONTRACT.md`, and `schemas/manipulation_signal.schema.json`.

## Not the same technology

- **AMAS-AUTH** decides which authorized sources may control which states or actions.
- **AMAS-MANIP** proposes evidence-linked analysis of potential manipulation or cognitive distortion.
- The **AMAS Integrity Plane** is the proposed composition, not a merged specification or implicit promotion of model-produced annotations into policy.
- **Symbalics** is the separate cognition plane potentially consuming annotations and governed state transitions.

The included JSON schema/test is an *interface-shape check*, not a detection algorithm or scientific validation.

