# AMAS / AAB / AMCS Threat Model

## Scope

This document identifies threats the current AMAS Core, Runtime Binding, AMCS, and AAB reference architecture are designed to mitigate or expose.

AMAS/AAB is a governance/enforcement architecture, not a replacement for operating-system, network, hypervisor, hardware, or supply-chain security.

## Context and memory authority threats

### T1 — Tier impersonation
Low-authority content impersonates a higher-authority source. Authority is derived from trusted source/ingestion metadata, not wording.

### T2 — Data-as-instruction / same-tier prompt injection
Retrieved evidence, quoted material, or tool observations contain imperative text and are treated as directives merely because they share the same contextual tier as legitimate user/runtime material.

**Mitigation:** AMAS 2.0-draft now separates `authority_tier` from `semantic_role`. `EVIDENCE`, `OBSERVATION`, and `INFERENCE` cannot directly authorize behavior. A non-directive → directive transition requires a new object created by an already-authorized issuer.

**Residual risk:** incorrect or compromised ingestion/segmentation metadata can misclassify semantic role.

### T3 — Implicit inference escalation
Model-generated inference becomes established authority. Tier 3 is bound to `INFERENCE`; inference cannot be a direct directive.

### T4 — Provenance opacity / authority laundering
A consequential decision cannot be traced to an authorized source. AMAS requires explicit source, role, tier, scope, transition, and provenance surfaces.

### T5 — Canonical-root ambiguity
Multiple artifacts are treated as canonical. Core doctrine requires one canonical root proven unique before hydrate completes.

### T6 — Writable truth-source drift
Multiple writable truth surfaces emerge. Core doctrine permits one writable truth ledger for an active context.

### T7 — Silent repair or mutation
Infrastructure rewrites authoritative state without an explicit receipt. Silent repair and silent canonical replacement are forbidden.

### T8 — Derived artifacts become de facto canon
Indexes, summaries, graphs, or rollups gate canonical reads or silently define truth. Derived artifacts may aid retrieval but cannot elevate authority or semantic role.

### T9 — Conflict-arbitration ambiguity
Two conforming implementations choose different winners for identical authority conflicts.

**Mitigation:** structural `scope_path` specificity, specificity before recency, and one fail-closed Rule 5 result (`HALT_ESCALATE`).

## AMCS persistence threats

### T10 — Archive traversal / special-file extraction
A malicious cell archive writes outside the extraction root or creates links/devices/FIFOs.

**Mitigation:** bounded manual extraction, path containment, duplicate-member rejection, and link/special-file rejection.

### T11 — Attachment-root escape
Attachment metadata attempts absolute or `..` path escape.

**Mitigation:** attachments require an explicit root and resolved descendants only.

### T12 — Artifact clobbering
A new seal silently replaces an existing immutable cell or supercell.

**Mitigation:** no-clobber exclusive archive creation; an existing destination causes failure.

### T13 — Partial/invalid seal published as authoritative
Verification fails but an archive is still emitted.

**Mitigation:** pre-seal and final verification are blocking; failure emits no final bundle.

### T14 — Metadata/content rebinding
Cell scope, canonical-source metadata, index information, or content manifest is changed independently.

**Mitigation:** `cell_root.json` cryptographically binds the content-manifest hash, seal-receipt hash, and cell-index hash. Optional HMAC root authentication is available in the reference implementation.

**Residual risk:** an unauthenticated root can be recomputed by an attacker. Production authenticity requires a protected signing/anchoring key or external trust service.

### T15 — Prompt/response omission
A user prompt disappears from causality accounting.

**Mitigation:** every user prompt must be mapped to a response or explicitly marked `no_response_required`; unresolved prompts block sealing.

### T16 — Schema/runtime drift
Generated artifacts violate the repository's own schemas while CI remains green.

**Mitigation:** generated-cell conformance tests validate prompt log, response map, case-study graph, cell index, seal receipt, cell root, and supercell manifest against Draft 2020-12 schemas.

## Agent action authority threats

### T17 — Objective / target substitution
The agent replaces the authorized task or target with a useful but unauthorized one.

**Mitigation:** explicit objective/target scope plus effective adapter resolution.

### T18 — Destination / network expansion
A reachable host/API/proxy is treated as permission.

**Mitigation:** destination allowlists and capability-contract effective-destination rules.

### T19 — Ambient credential use
The agent discovers credentials not delegated for the action.

**Mitigation:** explicit credential scope in policy and capability contract.

### T20 — Privilege / side-effect expansion
An operation expands from observation/simulation to persistent or privileged change.

**Mitigation:** externally enforced side-effect ceiling based on the effective prepared action.

### T21 — Parameter/effect smuggling through an allowed operation
The operation/destination is nominally allowed but parameters induce local-file access, redirects, subprocesses, or secondary network effects.

**Mitigation:** adapter-specific capability contracts constrain allowed parameter keys/values and declared security effects.

**Residual risk:** the trusted adapter must correctly model the effect semantics that matter for its tool/protocol.

### T22 — Budget/rate expansion
Intermediate success or repeated requests exceed delegated action/network/egress/time budgets.

**Mitigation:** broker-owned cumulative counters and deny-by-default budget checks.

### T23 — Unauthorized delegation / sub-agent widening
Delegation creates a child with broader effective capability.

**Mitigation:** machine-verified subset relations include objectives, operations, targets, destinations, credentials, capability contracts, side effects, budgets, expiry, and depth.

### T24 — Success-derived authority
An unexpected successful action is treated as permission to continue or broaden scope.

**Mitigation:** success is not an authority transition.

### T25 — Action laundering through model rationale
A model explanation/recommendation is treated as authorization.

**Mitigation:** authorization derives from the external lease/policy, not model-generated rationale.

## Enforcement-path threats

### T26 — Lease tampering
Targets, budgets, credentials, validity windows, or other lease fields are changed after issuance.

**Mitigation:** authenticated lease envelope; production keys must remain outside model reach.

### T27 — Premature / revoked lease use
A correctly signed lease is used before its validity window or after an emergency revocation.

**Mitigation:** `not_before`, policy expiry, and external revocation hook.

**Residual risk:** production revocation availability/integrity is deployment-specific.

### T28 — Action-request replay
A prior valid request is reused.

**Mitigation:** minimum-format nonce, nonce uniqueness, exact monotonic request sequence, and freshness window.

### T29 — Agent-supplied budget spoofing
The agent reports lower usage to regain budget.

**Mitigation:** authoritative usage is broker-owned; adapter cost is trusted enforcement metadata.

### T30 — Authorization-to-execution substitution
The broker authorizes one action but the caller/adapter later dispatches another.

**Mitigation:** immutable `PreparedAction`; exact SHA-256 action hash is passed to the broker and included inside the chained decision receipt; dispatch requires a matching binding hash.

### T31 — Decision-log mutation / reordering
Receipts are edited to obscure broker behavior.

**Mitigation:** monotonic SHA-256 receipt chain.

**Residual risk:** a local chain alone cannot prove non-truncation; external checkpoint/anchoring is complementary.

### T32 — Restart resets authority state
Restart loses nonces, sequence, counters, or receipts.

**Mitigation:** authenticated durable broker state.

### T33 — Concurrent double spending of authority
Two broker instances authorize against the same stale budget/sequence snapshot.

**Mitigation:** reference state version 2 uses a SQLite `BEGIN IMMEDIATE` sidecar transaction; each authorization reloads the newest authenticated state under lock before evaluation.

**Residual risk:** this is a local reference transaction model, not a distributed-consensus design.

### T34 — Rollback to an older authenticated state
An older state with a valid MAC restores spent authority.

**Mitigation:** independently retained checkpoint comparing generation, state hash, receipt count, and receipt tip.

### T35 — Higher-generation divergent fork
An attacker presents a state with a larger generation that is not descended from the checkpointed state.

**Mitigation:** state v2 records explicit state-hash ancestry; higher-generation restoration must prove checkpoint ancestry and receipt-chain extension.

### T36 — Incomplete mediation topology
An alternate adapter, proxy, plugin, subprocess, RPC, network route, credential path, collaborating agent, or equivalent-effect sink bypasses AAB.

**Mitigation:** structural broker-removal reachability test over the declared graph, plus architecture-specific empirical evaluation for A4.

**Residual risk:** the topology proof is only as complete as the real capability enumeration.

### T37 — Compromised enforcement plane
The broker, trusted adapter, sandbox boundary, credential service, signing/revocation/checkpoint service, OS, or equivalent enforcement component is compromised.

AAB cannot recover containment after the trusted boundary itself is lost.

## Partially addressed / future work

### T38 — Multi-agent authority negotiation and revocation propagation
Monotonic delegation exists, but cross-provider identity, mutually distrustful principals, distributed revocation, and partial-failure semantics remain incomplete.

### T39 — Real-world change invalidates an unexpired grant
Expiry/revocation provide mechanisms, but determining when external circumstances invalidate authority is deployment-specific.

### T40 — Information-flow confidentiality
Egress-byte budgets and destination restrictions constrain some channels but do not by themselves implement taint tracking, secret classification, or noninterference. High-assurance deployments should add secret isolation and information-flow controls appropriate to the system.

## Evidence discipline

The existence of AMAS/AAB documentation or reference code is not evidence that a deployment contains a frontier agent. Containment claims require architecture-specific adversarial testing, reviewable real topology, trusted adapter/effect modeling, authoritative transactional state, rollback/fork evidence, and reproducible results.
