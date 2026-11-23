# Adaptive Manipulation Analysis System — Research Specification

**Identifier:** AMAS-MANIP
**Version:** research-draft 0.1 (documentation only; not a canonical release)
**Evidence status:** proposed and unvalidated
**Scope:** detection and characterization of *candidate* manipulation/cognitive-integrity signals; no security authority or tool execution.

## Research objective

Test whether structured, provenance-linked review of incoming information and proposed state transitions can reduce authority laundering, frame capture, correction resistance, and ungrounded epistemic promotion *without suppressing legitimate emotion, dissent, atypical expression, or creative thought*.

## Candidate signal families

| Family | Observables to investigate | Illustrative non-malicious alternative |
| --- | --- | --- |
| Provenance weakness | Missing, circular, or uncheckable source lineage | Unavailable archive; informal conversation |
| Authority spoofing | Source asserts rights or privileged status without verified authorization | Quotation, warning, hypothetical |
| Repetition without independent evidence | Repeated claims exert influence while evidence count is unchanged | Emphasis, reminders, pedagogy |
| Emotional leverage / urgency | Pressure to decide without adequate review | Genuine time-sensitive need |
| Identity overwrite / affiliation pressure | Attempt to replace a person's declared preferences or identity with unsourced claims | Good-faith disagreement |
| Epistemic drift | Reported, imagined or inferred content represented as direct observation | Editing error or ambiguity |
| Frame or attention capture | One interpretation dominates despite corrections or competing relevant intents | High-priority single issue |
| Privacy/action pressure | Request for sensitive inference, disclosure, destination switch or premature effect | Authorized urgent transaction |
| Burden reversal, false dilemmas, selective literalism | Distortion of evidence burden or over-narrow readings | Rhetorical compression |
| Procedural capture | Workflow or evaluation procedure is redirected by untrusted content | Legitimate change request |

These are **candidate analytical categories**, not proof that a person is manipulating or that a source is false. Classification must preserve counterevidence and alternative explanations.

## Proposed invariants

1. Preserve the quoted/original source and provenance for each claimed indicator; do not fabricate source references.
2. Separate observation (what text/activity is seen), interpretation (possible pattern), and intent attribution (often unknown).
3. Keep any candidate risk score as a vector of calibrated, domain-specific measurements *if independently validated*; never turn an uncalibrated score into a fact or accusation.
4. Permit broad internal hypothesis generation while preventing unsupported factual promotion, authoritative writes, publication, or action.
5. When evidence, confidence, domain calibration or alternatives are insufficient, support abstention and review.
6. Make corrections propagate into dependent proposals, retrieval hypotheses and output planning; this capability is **not yet implemented**.
7. Avoid bias against vulnerable speakers or controversial but lawful views; report false-positive and false-negative rates in evaluations.
8. Protect private data and limit downstream disclosure; structured audit evidence is preferable to exposing raw private reasoning.
9. A manipulation hypothesis does not supersede operator instructions, canonical context, facts, or policy. Existing AMAS-AUTH semantic-role admission remains controlling.
10. External action authorization must pass through an independently trusted gate and exact target/effect checks described in AAB; never through a model-produced manipulation signal.

## Proposed processing boundary

`Input → evidence/provenance typing → candidate indicator annotations → alternatives and uncertainty → governance-side review → advisory output`

AMAS-MANIP may recommend that a proposal be **reviewed, attenuated, deferred, or quarantined**, but these are *advisory recommendations*. Only an authorized policy/runtime boundary can actually deny, quarantine, publish, write authoritative state, or execute an action.

## Evaluation requirements

- Define candidate signals and annotation guidelines before evaluation.
- Include counterexamples: emotional but truthful testimony; repeated reminders; unpopular dissent; satire; fiction; lawful advocacy.
- Evaluate with diverse independent annotators, and audit subgroup errors.
- Report precision/recall and calibration only where labels and datasets support them; monitor false accusation rates.
- Compare against evidence-tagging only, existing prompt-injection heuristics, and matched-compute baselines.
- Test attacks that exploit the detector itself: fake flags, fabricated source IDs, selective evidence, and score-to-authority laundering.
- Publish failure cases and residual risks; do not claim successful detection from a passing JSON schema test.

## Nonclaims

This text does not claim a working implementation, human motive detection, forensic certainty, protection against arbitrary attacks, evidence of conspiracy, or clinical/psychological diagnosis.

