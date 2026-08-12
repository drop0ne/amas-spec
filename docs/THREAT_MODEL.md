# AMAS Threat Model

## Scope

This document identifies threats AMAS Core, Runtime Binding, AMCS, and the Agent Authority Boundary (AAB) are designed to mitigate or constrain. AMAS is a governance and enforcement architecture, not a replacement for infrastructure security.

## Context and memory threats

### T1 — Tier impersonation / prompt injection
Low-authority content impersonates a higher-authority source. Authority is assigned from source identity and ingestion metadata, not persuasive wording.

### T2 — Implicit inference escalation
Model-generated inference is treated as established authority. Tier 3 cannot silently promote itself.

### T3 — Provenance opacity / authority laundering
A consequential decision cannot be traced to an authorized source. AMAS requires provenance and explicit tier transitions.

### T4 — Canonical-root ambiguity
Multiple artifacts are treated as canonical. Core doctrine requires one canonical root proven unique before hydrate completes.

### T5 — Writable truth-source drift
Multiple writable truth surfaces emerge. Core doctrine permits one writable truth ledger for an active context.

### T6 — Silent repair or mutation
Infrastructure rewrites authoritative state without explicit receipt. Silent repair and silent chain-tip replacement are forbidden.

### T7 — Derived artifacts gating reads
Indexes, manifests, summaries, or rollups become de facto canon. Derived artifacts may summarize truth but may not define truth or gate canonical reads.

### T8 — Receipt replay
A valid but stale activation/export artifact is reused against newer state. Runtime bindings should verify freshness and state hashes.

## Agent action threats

### T9 — Target substitution
The agent substitutes a useful but unauthorized target. Explicit target scope denies this.

### T10 — Destination / network expansion
A reachable host, registry, API, or route is treated as permission. AAB separates reachability from authorization.

### T11 — Ambient credential use
The agent discovers credentials not delegated for the action. Unlisted credentials fail closed.

### T12 — Privilege / side-effect expansion
The agent escalates from observation/simulation to persistent or privileged change. AAB enforces an external side-effect ceiling.

### T13 — Budget / rate expansion
Intermediate success is used to justify continued activity. AAB binds action, network, egress, and wall-clock budgets.

### T14 — Unauthorized delegation / sub-agent spawning
Delegation is used to obtain broader effective capability. AAB requires monotonic child authority.

### T15 — Action laundering
Model-generated rationale is treated as authorization. Authorization must derive from the external lease, not the model explanation.

### T16 — Success-derived authority
Unexpected success is treated as permission to continue. Success does not widen scope.

## Enforcement-path threats

### T17 — Authority-lease tampering
Targets, credentials, budgets, ceilings, or expiry are edited after grant. AAB 0.3 authenticates the reference lease envelope.

Residual risk: the reference HMAC mechanism is demonstrative; production key authority should remain outside the model environment.

### T18 — Action-request replay
A previously valid request is submitted again. AAB uses nonces, monotonic sequences, and freshness windows.

### T19 — Agent-supplied budget spoofing
The agent reports lower usage to regain budget. AAB 0.3 moves cumulative accounting to broker-owned state.

Residual risk: the broker/tool adapter must measure or conservatively reserve real action cost.

### T20 — Stale / future request acceptance
Old envelopes are replayed or time metadata is manipulated. The broker enforces freshness and rejects materially future-dated requests.

Residual risk: broker clock integrity is an infrastructure dependency.

### T21 — Authorization-log mutation / reordering
Decision records are edited to obscure broker behavior. Receipt chaining detects mutation and reordering in an observed chain.

Residual risk: hash chaining alone does not prove the complete chain has not been truncated.

### T22 — Enforcement-path bypass
The agent reaches a tool, credential, subprocess, network interface, service, or equivalent-effect channel without traversing AAB.

AAB cannot solve this in policy code alone. Strong containment requires architecture-level mediation and conventional isolation controls.

## AAB 0.4 durability and topology threats

### T23 — Broker restart resets authority state
A broker process restarts and loses consumed nonces, sequence state, budgets, or receipt history. The agent can then replay old requests or regain spent authority.

**AAB 0.4 mitigation:** authenticated durable broker state persists replay state, counters, request sequence, and receipt history. Restart restoration verifies the state envelope and receipt chain.

**Residual risk:** durability depends on the correctness and availability of the persistence layer. Authorization must fail closed if persistence fails.

### T24 — Rollback to an older but valid broker state
An attacker restores an older state object that still has a valid integrity MAC. Local integrity verification accepts the object even though it represents previously consumed authority.

**AAB 0.4 mitigation:** an independently retained signed checkpoint records state generation, state hash, and receipt-chain tip. Restored state older than the checkpoint, or equal-generation state with a different hash/tip, fails closed.

**Residual risk:** a checkpoint stored in the same compromise domain can be rolled back with the state. High-assurance deployments must anchor it in an independent failure domain.

### T25 — Incomplete mediation topology
The documented architecture shows all known side effects crossing AAB, but an omitted alternate adapter, proxy, RPC channel, plugin, subprocess, credential path, or equivalent-effect sink remains available.

**AAB 0.4 mitigation:** `reference/mediation_graph.py` rejects any *modeled* agent→side-effect path that does not include a broker, and the bypass corpus tests common topology errors.

**Residual risk:** structural graph verification is only as complete as the declared graph. A4 requires architecture-specific enumeration and empirical testing against the real environment.

### T26 — Checkpoint / state evidence tampering
An attacker edits a persisted state envelope or checkpoint.

**AAB 0.4 mitigation:** both state and checkpoint records are integrity protected in the reference implementation; receipt chains are reverified during restoration.

**Residual risk:** compromise of integrity keys invalidates this assurance.

## Partially addressed

### T27 — Multi-agent authority negotiation
Monotonic delegation is implemented, but the repository does not yet define a complete distributed negotiation protocol covering mutually distrustful agents, revocation propagation, partial failures, or cross-provider identity.

### T28 — Stale authority due to real-world change
Expiry constrains stale leases, but determining when external circumstances invalidate an otherwise unexpired grant remains deployment-specific.

### T29 — Compromised enforcement plane
If the broker, policy service, sandbox boundary, credential broker, signing/checkpoint service, or equivalent enforcement component is compromised, the model may act outside AMAS.

## Outside scope / complementary controls

- compromised Tier 0/platform channel
- malicious actors legitimately holding sufficient authority
- model-weight or training-data compromise
- hardware/firmware compromise
- side channels outside the instrumented action path
- vulnerabilities in enforcement components themselves
- physical effects the deployment cannot observe or mediate

Production deployments should combine AMAS/AAB with least privilege, process isolation, egress filtering, secret isolation, durable replay state, independent checkpoint anchoring, tamper-evident logs, monitoring, and incident response.

## Evidence discipline

The existence of AAB documentation or reference code is not evidence that a deployment contains a frontier agent. Containment claims require architecture-specific adversarial testing, a reviewable mediation topology, evidence that restart/rollback cannot restore spent authority, and reproducible results showing the evaluated agent cannot exercise an equivalent unmediated path.
