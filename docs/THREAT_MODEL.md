# AMAS Threat Model

## Scope

This document identifies threats AMAS Core, Runtime Binding, AMCS, and the Agent Authority Boundary (AAB) are designed to mitigate or constrain. AMAS is a governance and enforcement architecture, not a replacement for infrastructure security.

## Context and memory threats

### T1 — Tier impersonation / prompt injection
Low-authority content impersonates a higher-authority source. Authority is assigned from source identity and ingestion metadata, not persuasive wording. Residual risk: source misclassification or compromised high-authority channels.

### T2 — Implicit inference escalation
Model-generated inference is treated as established authority. Tier 3 requires explicit inference marking and cannot silently promote itself.

### T3 — Provenance opacity / authority laundering
A consequential decision cannot be traced to an authorized source. AMAS requires provenance and makes tier transitions explicit.

### T4 — Canonical-root ambiguity
Multiple artifacts are treated as canonical. Core doctrine requires exactly one canonical root proven unique before hydrate completes.

### T5 — Writable truth-source drift
Multiple writable truth surfaces emerge. Core doctrine permits exactly one writable truth ledger for an active context.

### T6 — Silent repair or mutation
Infrastructure rewrites authoritative state without explicit receipt. Silent repair and silent chain-tip replacement are forbidden.

### T7 — Derived artifacts gating reads
Indexes, manifests, summaries, or rollups become de facto canon. Derived artifacts may summarize truth but must not define truth or gate canonical reads.

### T8 — Receipt replay
A valid but stale activation/export artifact is reused against newer state. Runtime bindings should verify freshness and state hashes.

## Agent action threats

### T9 — Target substitution
An agent replaces the authorized target with another target that appears useful for the objective. AAB requires explicit target scope; useful is not equivalent to authorized.

### T10 — Destination / network expansion
The agent discovers a reachable host, service, registry, API, or route and treats discovery as permission. AAB separates reachability from authorization and denies unlisted destinations.

### T11 — Ambient credential use
The agent discovers or inherits credentials that were not delegated for the action. AAB requires explicit credential references; unlisted credentials fail closed.

### T12 — Privilege or side-effect expansion
The agent moves from observation/simulation to persistent or privileged changes. AAB enforces an ordered side-effect ceiling outside the model.

### T13 — Budget and rate expansion
The agent continues acting because intermediate steps succeed. AAB binds cumulative action, network, egress, and wall-clock budgets to the authority lease.

### T14 — Unauthorized delegation / sub-agent spawning
An agent delegates to another agent to obtain a broader effective capability. AAB requires monotonic delegation: child authority cannot exceed parent authority.

### T15 — Action laundering
Model-generated rationale is treated as authorization for a side effect. AAB requires authorization to derive from the external lease, not the model's explanation.

### T16 — Success-derived authority
A successful unauthorized or unexpected intermediate action is treated as permission to continue. AAB explicitly forbids success from widening scope.

## Partially addressed

### T17 — Multi-agent authority dilution
AAB defines monotonic delegation rules, but the repository does not yet provide a complete inter-agent negotiation protocol or production-grade child-policy verifier.

### T18 — Stale authority
Policy expiration constrains stale leases, but determining when real-world circumstances invalidate an otherwise unexpired grant remains deployment-specific.

### T19 — Compromised enforcement plane
If the tool broker, policy service, sandbox boundary, credential broker, or other enforcement plane is bypassed or compromised, the model may act outside AMAS. Defense requires conventional security controls and independent monitoring.

## Outside scope / complementary controls required

- compromised Tier 0/platform channel
- malicious actors who legitimately hold sufficient authority
- model-weight or training-data compromise
- hardware/firmware compromise
- side channels outside the instrumented action path
- vulnerabilities in enforcement components themselves

Production deployments should combine AMAS/AAB with least privilege, process isolation, network egress filtering, secret isolation, immutable/tamper-evident logs, independent monitoring, and incident response.

## Evidence discipline

The existence of AAB documentation or reference code is not evidence that a deployment contains a frontier agent. Containment claims require architecture-specific adversarial testing and reproducible results.
