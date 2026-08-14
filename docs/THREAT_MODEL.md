# AMAS / AAB / AMCS Threat Model

## Scope

This document identifies threats the current AMAS Core, Runtime Binding, AMCS, and AAB reference architecture are designed to mitigate or expose.

AMAS/AAB is a governance/enforcement architecture, not a replacement for operating-system, network, hypervisor, hardware, identity-provider, or supply-chain security.

## Context and memory authority threats

### T1 — Tier impersonation
Low-authority content impersonates a higher-authority source.

**Mitigation:** authority derives from trusted source/ingestion metadata, not wording.

### T2 — Data-as-instruction / same-tier prompt injection
Retrieved evidence, quoted material, or tool observations contain imperative text and are treated as directives merely because they share the same contextual tier as legitimate user/runtime material.

**Mitigation:** `authority_tier` is separate from `semantic_role`. `EVIDENCE`, `OBSERVATION`, and `INFERENCE` cannot directly authorize behavior. A non-directive → directive transition requires a new object created by an already-authorized issuer.

**Residual risk:** incorrect or compromised ingestion/segmentation metadata can misclassify semantic role.

### T3 — Implicit inference escalation
Model-generated inference becomes established authority.

**Mitigation:** Tier 3 is bound to `INFERENCE`; inference cannot be a direct directive.

### T4 — Provenance opacity / authority laundering
A consequential decision cannot be traced to an authorized source.

**Mitigation:** Memory Objects carry source, role, tier, scope, transition, and provenance surfaces; runtime activation/mutation/export remains auditable.

### T5 — Self-asserted supersession
A same-tier object names another object in `supersedes` and thereby acquires authority without proving that the issuer was allowed to supersede it.

**Mitigation:** full Memory Object admission, forward-traceable supersession provenance, and a trusted external `supersession_authorizer`. Missing, false, malformed, unavailable, or exception-raising authorization fails closed to Rule 5.

**Residual risk:** correctness/availability of the trusted authority service remains deployment-specific.

### T6 — Malformed high-tier object wins partial-field arbitration
A runtime reads only tier/role fields from a schema-invalid object and lets it override valid lower-tier state.

**Mitigation:** full Memory Object admission precedes conflict arbitration.

### T7 — Canonical-root ambiguity
Multiple artifacts are treated as canonical.

**Mitigation:** Core doctrine requires one canonical root proven unique before hydrate completes.

### T8 — Writable truth-source drift
Multiple writable truth surfaces emerge.

**Mitigation:** Core doctrine permits one writable truth ledger for an active context.

### T9 — Silent repair or mutation
Infrastructure rewrites authoritative state without an explicit receipt.

**Mitigation:** silent repair/canonical replacement are forbidden.

### T10 — Derived artifacts become de facto canon
Indexes, summaries, graphs, or rollups silently define truth.

**Mitigation:** derived artifacts may aid retrieval but cannot elevate authority or semantic role.

### T11 — Conflict-arbitration ambiguity
Two conforming implementations choose different winners for identical authority conflicts.

**Mitigation:** explicit ordering, structural `scope_path` specificity, specificity before recency, trusted supersession authorization, and one fail-closed Rule 5 result (`HALT_ESCALATE`).

## AMCS persistence threats

### T12 — Archive traversal / special-file extraction
A malicious cell archive writes outside extraction root or creates links/devices/FIFOs.

**Mitigation:** bounded manual extraction, path containment, duplicate-member rejection, and link/special-file rejection.

### T13 — Attachment-root escape
Attachment metadata attempts absolute or `..` path escape.

**Mitigation:** attachments require an explicit root and resolved descendants only.

### T14 — Artifact clobbering
A new seal silently replaces an existing immutable cell/supercell.

**Mitigation:** no-clobber exclusive archive creation.

### T15 — Partial/invalid seal published as authoritative
Verification fails but an archive is still emitted.

**Mitigation:** pre-seal/final verification are blocking; schema-validating conformance sealing removes an emitted archive when claimed generated JSON surfaces fail validation.

### T16 — Metadata/content rebinding
Cell scope, canonical-source metadata, index information, or content manifest is changed independently.

**Mitigation:** `cell_root.json` binds content-manifest hash, seal-receipt hash, and cell-index hash. Optional HMAC root authentication is available.

**Residual risk:** an unauthenticated root can be recomputed. Higher-assurance authenticity needs a protected signing/anchoring service.

### T17 — Prompt/response omission
A user prompt disappears from causality accounting.

**Mitigation:** every prompt maps to a response or explicit `no_response_required`; unresolved prompts block sealing.

### T18 — Schema/runtime drift
Generated artifacts or accepted input violate repository schemas while ordinary round-trip tests remain green.

**Mitigation:** `reference/amcs_runtime.py` is the supported conformance entrypoint. It validates supported JSON input before sealing and validates claimed generated JSON surfaces against Draft 2020-12 schemas. CI includes a negative invalid-input seal test.

### T19 — AMCS semantic overclaim
Archive assembly is described as if it automated richer semantic operations it does not implement.

**Mitigation:** claim boundary is explicit: the reference binds/copies ODT evidence but does not parse ODT semantics into structured canonical narrative; supercell assembly verifies/bundles children but does not automate semantic contradiction/authority reconciliation.

## Agent action authority threats

### T20 — Objective / target substitution
The agent replaces the authorized task/target with an unauthorized one.

**Mitigation:** explicit objective/target scope plus effective adapter resolution.

### T21 — Destination / network expansion
A reachable host/API/proxy is treated as permission.

**Mitigation:** destination allowlists and capability-contract effective-destination rules.

### T22 — Ambient credential use
The agent discovers credentials not delegated for the action.

**Mitigation:** explicit credential scope in policy and capability contract.

### T23 — Privilege / side-effect expansion
An operation expands from observation/simulation to persistent or privileged change.

**Mitigation:** externally enforced side-effect ceiling based on effective prepared action.

### T24 — Parameter/effect smuggling through an allowed operation
Nominally allowed parameters induce local-file access, redirects, subprocesses, or secondary network effects.

**Mitigation:** adapter-specific content-addressed capability contracts constrain parameter keys/values and declared effects.

**Residual risk:** the trusted adapter must correctly model security-relevant semantics.

### T25 — Budget/rate expansion
Repeated requests exceed delegated action/network/egress/time budgets.

**Mitigation:** broker-owned cumulative counters and deny-by-default budget checks.

### T26 — Unauthorized delegation / sub-agent widening
Delegation creates a child with broader effective capability or schema-invalid hidden fields.

**Mitigation:** shared closed policy admission plus machine-verified subset relations across objectives, operations, targets, destinations, credentials, capability contracts, side effects, budgets, expiry, and depth; exact parent ID/hash binding.

### T27 — Success-derived authority
Unexpected success is treated as permission to continue/broaden scope.

**Mitigation:** success is not an authority transition.

### T28 — Action laundering through model rationale
A model explanation/recommendation is treated as authorization.

**Mitigation:** authorization derives from external authenticated policy, not model rationale.

## Enforcement-path threats

### T29 — Lease tampering or schema-smuggling
Targets/budgets/credentials/validity fields are changed, or a signed envelope carries unknown fields interpreted differently by different components.

**Mitigation:** authenticated lease plus exact closed lease/policy admission shared across broker/gate/delegation.

### T30 — Premature / revoked lease use
A correctly signed lease is used before validity or after emergency revocation.

**Mitigation:** `not_before`, expiry, and fail-closed external revocation hook.

### T31 — Action-request replay
A prior request is reused.

**Mitigation:** nonce uniqueness, monotonic sequence, and freshness window.

### T32 — Agent-supplied budget spoofing
The agent reports lower usage to regain budget.

**Mitigation:** usage is broker-owned; adapter cost is trusted enforcement metadata.

### T33 — Authorization-to-execution substitution
The broker authorizes one action but a different one is dispatched.

**Mitigation:** immutable `PreparedAction`; exact action hash is inside the chained broker receipt; dispatch requires matching binding.

### T34 — Post-dispatch completion ambiguity / unsafe retry
An external effect may occur, then the adapter response is lost or raises; caller interprets the exception as “nothing happened” and retries.

**Mitigation:** transactional completion journal writes `STARTED` before dispatch, then `SUCCEEDED` or `OUTCOME_UNKNOWN`. Recovered lingering `STARTED` is `OUTCOME_UNKNOWN`. Result-serialization failure after adapter return does not downgrade the completed effect. `OUTCOME_UNKNOWN` is not an automatic retry signal.

**Residual risk:** arbitrary remote systems do not become exactly-once transactional systems. Service-specific idempotency/reconciliation may be required.

### T35 — Decision/completion evidence mutation
Receipts or exported completion records are edited.

**Mitigation:** broker decision receipts are hash chained; completion records bind authorization receipt hash and action hash. Portable completion shape is closed by `schemas/effect_completion.schema.json`.

**Residual risk:** a local unanchored chain/journal cannot independently prove non-truncation.

### T36 — Restart resets authority state
Restart loses nonces, sequence, counters, or receipts.

**Mitigation:** authenticated durable broker state.

### T37 — Concurrent double spending of authority
Two broker instances authorize against one stale snapshot.

**Mitigation:** local reference uses SQLite `BEGIN IMMEDIATE` and reload-before-evaluate.

**Residual risk:** local transaction model is not distributed consensus.

### T38 — Rollback to an older authenticated state
An older state with valid MAC restores spent authority.

**Mitigation:** independently retained checkpoint comparing generation/state hash/receipt count/tip.

### T39 — Higher-generation divergent fork
A larger generation is not actually descended from checkpointed state.

**Mitigation:** explicit state-hash ancestry plus receipt-chain extension.

### T40 — Durable-state resource exhaustion
Complete nonce/receipt/ancestry history grows indefinitely and becomes a local resource-pressure path.

**Mitigation:** `BoundedDurableEnforcementBroker` supplies finite event epochs. Capacity exhaustion fails closed and requires explicit checkpoint/rotation; evidence is not silently discarded to regain capacity.

**Residual risk:** production compaction/log architecture remains deployment-specific.

### T41 — Incomplete mediation topology
An alternate adapter, proxy, plugin, subprocess, RPC, network route, credential path, collaborating agent, or equivalent-effect sink bypasses AAB.

**Mitigation:** structural broker-removal reachability test over the declared graph plus architecture-specific empirical evaluation for A4.

**Residual risk:** topology proof is only as complete as actual capability enumeration.

### T42 — Compromised enforcement plane
Broker, trusted adapter, sandbox boundary, credential/signing/revocation/checkpoint/completion service, OS, or equivalent enforcement component is compromised.

AAB cannot recover containment after the trusted boundary itself is lost.

### T43 — Cross-language serialization/type ambiguity
Different language runtimes hash or interpret the same security object differently because of integer width, boolean/integer conflation, pointer/size/time representations, or serializer differences.

**Mitigation:** Canonical JSON v1 plus fixed-width C/C++ portable type profile and C11/C++17 compile checks.

## Partially addressed / future work

### T44 — Multi-agent authority negotiation and revocation propagation
Monotonic delegation exists, but cross-provider identity, mutually distrustful principals, distributed revocation, and partial-failure semantics remain incomplete.

### T45 — Real-world change invalidates an unexpired grant
Expiry/revocation provide mechanisms, but determining when external circumstances invalidate authority is deployment-specific.

### T46 — Information-flow confidentiality
Egress-byte budgets/destination restrictions do not themselves implement taint tracking, secret classification, or noninterference. High-assurance deployments should add secret isolation/information-flow controls.

## Evidence discipline

The existence of documentation/reference code or a passing CI suite is not evidence that a deployment contains a frontier agent. Containment claims require architecture-specific adversarial testing, reviewable real topology, trusted adapter/effect modeling, authoritative transactional state, completion/reconciliation evidence, rollback/fork evidence, and reproducible results.
