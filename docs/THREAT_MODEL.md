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
An agent delegates to another agent to obtain a broader effective capability. AAB requires monotonic delegation: child authority cannot exceed parent authority. The reference verifier/deriver rejects child-policy widening across the defined authority dimensions.

### T15 — Action laundering
Model-generated rationale is treated as authorization for a side effect. AAB requires authorization to derive from the external lease, not the model's explanation.

### T16 — Success-derived authority
A successful unauthorized or unexpected intermediate action is treated as permission to continue. AAB explicitly forbids success from widening scope.

## Enforcement-path threats

### T17 — Authority-lease tampering
An agent or intermediary edits targets, credentials, budgets, side-effect ceilings, or expiry after authority was granted. AAB 0.3 introduces authenticated lease envelopes. Any modification to a signed lease invalidates the reference signature.

Residual risk: the reference HMAC mechanism uses symmetric material. Production systems should keep signing authority outside the model environment and choose a deployment-appropriate authentication mechanism.

### T18 — Action-request replay
A previously valid request is submitted again to repeat a side effect. AAB 0.3 binds requests to unique nonces, monotonic request sequences, and freshness windows.

Residual risk: replay state must survive broker restart when durable replay protection is required.

### T19 — Agent-supplied budget spoofing
The agent reports lower cumulative usage to regain action, network, egress, or time budget. AAB 0.3 moves enforcement-critical cumulative usage to broker-owned state and overwrites agent-supplied counters before policy evaluation.

Residual risk: the broker/tool adapter must measure or conservatively reserve action cost. Agent-controlled cost declarations are not sufficient.

### T20 — Stale or future-dated request acceptance
The agent reuses an old envelope or manipulates time metadata. AAB 0.3 rejects requests outside the configured freshness window and materially future-dated requests.

Residual risk: broker clock integrity remains an infrastructure dependency.

### T21 — Authorization-log mutation or reordering
An attacker edits or reorders decision records to obscure what the enforcement plane allowed or denied. AAB receipt chaining detects mutation and reordering within an observed chain.

Residual risk: hash chaining alone does not prevent full-chain truncation. Production deployments should independently anchor chain tips or use a durable append-only/signed store.

### T22 — Enforcement-path bypass
The agent reaches a tool, credential, network interface, subprocess, or service through a second path that does not traverse AAB.

AAB cannot solve this in policy code alone. Strong containment requires architecture-level mediation so all relevant side effects traverse the broker or an equivalent enforcement point, combined with OS/process isolation, egress controls, least-privilege credentials, and monitoring.

## Partially addressed

### T23 — Multi-agent authority negotiation
AAB now provides monotonic parent-to-child policy verification and derivation, but it does not yet define a complete distributed negotiation protocol covering mutually distrustful agents, revocation propagation, partial failures, or cross-provider identity.

### T24 — Stale authority due to changing real-world conditions
Policy expiration constrains stale leases, but determining when circumstances invalidate an otherwise unexpired grant remains deployment-specific.

### T25 — Compromised enforcement plane
If the tool broker, policy service, sandbox boundary, credential broker, signing service, or other enforcement component is compromised, the model may act outside AMAS. Defense requires conventional security controls and independent monitoring.

## Outside scope / complementary controls required

- compromised Tier 0/platform channel
- malicious actors who legitimately hold sufficient authority
- model-weight or training-data compromise
- hardware/firmware compromise
- side channels outside the instrumented action path
- vulnerabilities in enforcement components themselves
- physical effects that cannot be observed or mediated by the deployment

Production deployments should combine AMAS/AAB with least privilege, process isolation, network egress filtering, secret isolation, durable replay state, immutable/tamper-evident logs, independent monitoring, and incident response.

## Evidence discipline

The existence of AAB documentation or reference code is not evidence that a deployment contains a frontier agent. Containment claims require architecture-specific adversarial testing, evidence that the agent cannot bypass the enforcement path being evaluated, and reproducible results.
