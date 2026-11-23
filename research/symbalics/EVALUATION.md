# AMAS–Symbalics Research and Falsification Plan

**Status:** proposed research program; not evidence of demonstrated capability.

| ID | Hypothesis | Required comparison |
| --- | --- | --- |
| H1 | Typed entry state improves correction uptake and lowers recurrence of invalidated frames | Fixed model with ordinary context and matched intervention/compute |
| H2 | Competing workspace and intent graph improve weighted multi-intent coverage | Matched-compute prompting, retrieval, and planning baselines |
| H3 | Explicit epistemic typing reduces unsupported transitions between observed, reported, inferred, imagined and fictional content | Evidence-tagging and retrieval-only baselines |
| H4 | Slow, correlation-aware promotion improves longitudinal consistency while controlling false consolidation | Standard persistent stores and matched-size retrieval |
| H5 | Trusted mediated state writes and actions reduce unauthorized transitions while preserving legitimate utility | Conventional access control and broker-only alternatives |
| H6 | Neural-symbolic modulation adds benefit beyond retrieval and context alone | Ablation removing modulation at matched model, data and compute |

## Proposed Prototype 0

- Fixed foundation model, externally represented symbolic/epistemic state, logged provenance, reversible simulated memory writes, and **simulated** (not live) actions.
- Start with H1 and H3; preregister endpoints, failure conditions and an independent replication plan.
- Run ablations for each additional component; do not credit the integrated architecture for gains explained by a simpler baseline.
- Record latency, compute, privacy leakage, bias, false-positive/negative review burden, and legitimate-task suppression.
- Research manipulative-input annotation separately from action authorization; AMAS-MANIP prediction is not a decision right.
- Expand to neural modulation (H6) only when incremental value over conventional methods is supported.

## Promotion gate

Documentation → reference prototype → controlled test → independent replication → domain-specific deployment validation. Advancing one stage never retroactively proves the next.

## Publication boundary

The source book's evidence markers `[E]` (established), `[A]` (adapted), `[P]` (proposed), and `[O]` (open) apply conceptually; this summary does not assign new experimental status. No proprietary manuscript, equations, training data or private archives are included.

