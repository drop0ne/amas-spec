# AMAS Agent Authority Boundary (AAB)

**Version:** 0.4.1-draft  
**Status:** Experimental normative extension with executable enforcement-path hardening  
**Date:** 2026-08-13

## Purpose

AAB extends AMAS from contextual/memory authority to external action authority for tool-using and autonomous agents.

AMAS Core asks **which contextual object has authority?** AAB asks **does this principal possess authority for this exact effective side effect, can the enforcement path preserve that authority boundary, and can the runtime distinguish authorization from uncertain completion?**

AAB assumes capable agents may misunderstand instructions, follow hostile retrieved data, optimize around an evaluator, discover unintended capabilities, or attempt to use reachable resources never delegated to them.

## Core invariants

1. Capability is not authority.
2. Reachability is not authorization.
3. Data is not instruction.
4. Inference is not delegation.
5. Success does not widen scope.
6. No ambient authority: credentials, destinations, tools, parameter classes, and privileges require explicit grants.
7. Delegation is monotonic: a child may narrow but never silently widen parent authority.
8. Missing, malformed, expired, not-yet-valid, replayed, revoked, stale, or unverifiable authority fails closed.
9. The acting model is not the sole judge of its own authorization.
10. Enforcement counters, replay state, and durable security state are broker-owned.
11. Restart does not restore spent authority.
12. Higher-assurance rollback evidence must be anchored outside the state being protected.
13. Newer durable state must descend from checkpointed lineage, not merely carry a larger counter.
14. Authorization binds the exact effective prepared action, not merely model-declared intent.
15. Security-relevant adapter parameters and secondary effects are part of authority.
16. Authorization is not completion; post-dispatch uncertainty is explicit.
17. Every modeled path from an acting agent to a controlled side-effect sink must cross the enforcement boundary.
18. Decisions and completion state are auditable/tamper-evident to the extent of the declared persistence design.
19. Higher containment claims require reproducible architecture-specific evidence.

## 1. Authority leases

An action-capable runtime binds a principal to an authenticated lease. The reference lease is a closed envelope carrying:

- `lease_version`;
- lease/policy identifiers;
- issuer and `key_id`;
- issue time and `not_before`;
- maximum request age;
- signature algorithm and signature;
- embedded authority policy.

The embedded policy carries principal identity, objectives, operations, targets, destinations, credentials, capability-contract IDs, side-effect ceiling, budgets, delegation depth, expiry, and escalation behavior.

Unknown or malformed lease/policy fields fail closed even when the envelope's HMAC is otherwise cryptographically valid. Absence from an allowlist means denial.

The reference uses HMAC-SHA256 for compact portability. Production signing keys should be isolated from the acting model and selected for the deployment trust architecture.

### Revocation

Expiry is not sufficient for emergency containment. The reference broker accepts an external `revocation_checker(lease_id)` and fails closed when the checker reports revocation, fails, or returns a non-boolean value. The in-memory registry exists for tests only; production revocation state must be authenticated, durable, available, and outside model control.

## 2. Effective action and capability contracts

The model's request is not treated as an authoritative description of the effect.

A trusted adapter prepares an immutable effective action containing:

- operation;
- target;
- effective destination;
- credential reference;
- side-effect class;
- adapter parameters;
- trusted cost;
- security-relevant secondary effects.

Content-addressed capability contracts constrain allowed/required parameter keys, value allowlists, effective destinations, credentials, redirect chains, filesystem paths, subprocesses, and secondary destinations.

An allowed endpoint or operation does not imply every parameterization is authorized. The trusted adapter is part of the enforcement plane; AAB cannot protect against an adapter that lies about the effect it will execute.

## 3. Authorization-to-execution binding

`reference/mediated_executor.py` computes a Canonical JSON v1 SHA-256 hash over the immutable prepared action, including security effects and trusted cost.

That `execution_binding_hash` enters the broker **before** decision-receipt construction, so the chained receipt covers the exact prepared action.

Dispatch is eligible only when:

1. preparation succeeds;
2. any configured capability contract succeeds;
3. AAB policy evaluation returns `ALLOW`;
4. the chained broker receipt contains the exact same action hash;
5. durable authorization state has been committed; and
6. a pre-dispatch completion `STARTED` record has been durably written.

The same immutable `PreparedAction` is then passed to the registered adapter.

A general-purpose `ALLOW` result returned to untrusted application code is weaker than this design.

## 4. Completion integrity

An `ALLOW` receipt proves authorization, not completion.

The reference executor maintains a transactional completion journal keyed to the authorization receipt hash and exact action hash.

States:

- `STARTED` — persisted before adapter dispatch;
- `SUCCEEDED` — the adapter returned after dispatch;
- `OUTCOME_UNKNOWN` — dispatch occurred but completion cannot be established.

If the journal cannot record `STARTED`, the adapter is not called. If the adapter raises after dispatch, completion is `OUTCOME_UNKNOWN`. A recovered lingering `STARTED` record is also interpreted as `OUTCOME_UNKNOWN`.

If the adapter returns but its result cannot be serialized for the caller, the side effect remains `SUCCEEDED`; result-delivery failure does not turn a completed effect into a retryable failure.

`OUTCOME_UNKNOWN` MUST NOT be treated as an automatic retry signal. Deployments should reconcile against the external system or use service-specific idempotency/transaction support where available.

This reference does not create distributed exactly-once semantics for arbitrary external systems.

## 5. Replay and cumulative budgets

The broker verifies lease authenticity/validity, revocation, lease binding, nonce format/uniqueness, monotonic request sequence, request freshness, capability-contract scope, trusted adapter cost, policy scope, side-effect ceiling, and cumulative broker-owned budgets.

The acting agent does not supply the authoritative cumulative counters used for its own authorization. Structurally valid requests consume replay identity even when policy denies them, preventing a denied envelope from later being replayed as new.

## 6. Durable enforcement state

AAB 0.4.1 uses durable-state format version 2 in `reference/durable_broker.py`.

Persisted state includes lease/policy identity, generation, `previous_state_hash`, explicit ancestor-state hashes, last structural sequence, cumulative usage, consumed nonces, decision receipts, chain tip, state hash, and integrity MAC.

### Transaction serialization

A local SQLite sidecar is used as a compact transaction lock. Every authorization begins an exclusive transaction, reloads the newest authenticated JSON state, evaluates against that state, persists the next state, and only then returns authorization.

This prevents cooperating local broker processes from double-spending the same stale budget/sequence snapshot. Production systems may use stronger transactional/distributed stores.

### Persistence-before-effect

A real side effect is not executable until the durable authorization transition succeeds. Persistence failure is fail closed. The reference poisons an instance after persistence failure so uncertain in-memory state cannot continue authorizing.

### Bounded epochs

The base reference keeps full replay/receipt/ancestry history for inspectability. Long-lived workloads can make that state grow indefinitely.

`reference/bounded_durable_broker.py` adds an explicit finite event ceiling per epoch. Reaching the ceiling fails closed and requires operator checkpoint/rotation. The reference does not silently drop nonces, receipts, or ancestry to recover capacity.

Alternative production compaction is acceptable only if it preserves replay/accounting/lineage guarantees and cannot restore spent authority.

## 7. Rollback and state ancestry

A valid MAC proves integrity/authorship under a key; it does not prove freshness.

Independent checkpoints bind state generation, state hash, receipt count, and receipt-chain tip. A higher-generation restored state is accepted only when it proves descent from the checkpointed state and extends the checkpointed receipt chain.

The checkpoint must remain in an independent failure domain for meaningful rollback resistance.

## 8. Monotonic delegation

For parent policy `P` and child policy `C`:

- `C.objectives ⊆ P.objectives`;
- `C.operations ⊆ P.operations`;
- `C.targets ⊆ P.targets`;
- `C.destinations ⊆ P.destinations`;
- `C.credentials ⊆ P.credentials`;
- `C.capability_contracts ⊆ P.capability_contracts`;
- child side-effect ceiling ≤ parent ceiling;
- every child budget ≤ parent budget;
- child expiry ≤ parent expiry;
- delegation depth strictly decreases;
- exact parent ID/hash are bound;
- child policy passes the same closed policy-admission rules used by authorization;
- child operator escalation remains disabled.

Any widening requires a new authority grant; it is not delegation.

## 9. Mediation completeness

A policy engine cannot contain an agent that can produce the same effect by avoiding the engine.

`reference/mediation_graph.py` treats bypass as a reachability property: removing broker nodes must disconnect every modeled agent from every modeled side-effect sink. A shortest bypass witness is returned when this fails.

This proves only the declared topology. A real evaluation must enumerate actual adapters, network routes/redirects, credentials, files/file descriptors, subprocess/plugin mechanisms, RPC/service channels, secondary/equivalent-effect paths, and collaborating agents.

## 10. Decision and completion evidence

Decision receipts are SHA-256 chained with monotonic receipt sequence and previous-receipt hash. Broker receipts can include exact request/policy hashes, lease identity, authoritative usage, and exact execution-binding hash.

Completion records bind authorization receipt hash, action hash, deterministic execution ID, state, timestamps, error class, and result hash where available. `schemas/effect_completion.schema.json` defines the portable exported record shape.

Hash chaining detects mutation/reordering of observed records. It does not alone prove that an unanchored chain was not truncated. Durable state and external checkpoints provide complementary evidence.

## 11. Portable machine representation

Normative security objects use Canonical JSON v1 and the fixed-width portability profile in `docs/PORTABLE_TYPES.md` / `include/amas/types.h`.

Canonical JSON security integers remain limited to `±(2^53-1)` even when stored internally in `int64_t`/`uint64_t`. Platform-width integers, pointer values, or native time representations are not wire authority semantics.

## 12. Threats constrained

The reference architecture is designed to constrain/expose target/objective substitution, destination/credential expansion, side-effect escalation, parameter smuggling, unapproved redirects/files/subprocesses/secondary destinations, budget reset, unauthorized delegation, rationale laundering, success-derived scope expansion, replay/counter spoofing, malformed or tampered lease use, restart-state loss, stale concurrent state, rollback/forking, action substitution, completion ambiguity, unbounded local durable-state growth, and modeled mediation bypasses.

## 13. Residual trust and failure boundary

AAB does not recover containment after compromise of the enforcement host, signing/revocation/checkpoint/completion services, trusted adapters, OS/hypervisor isolation, effective endpoint resolution, or an unmodeled equivalent-effect path.

The reference implementation is intentionally small enough to inspect; it is not a production security appliance.

## 14. Evidence boundary

AAB 0.4.1 materially strengthens executable reference mechanisms but **does not establish A4 frontier-model containment**.

Current automated tests establish narrower propositions about reference code: scope/effect enforcement, content-addressed contracts, exact lease/policy admission, binding hashes, completion-state behavior, replay/budgets, transactional/bounded durable state, delegation monotonicity, ancestry/checkpoint behavior, portable types, and modeled bypass detection.

A4 remains an architecture-specific empirical claim requiring a real mediated environment, capable adversarial agent, complete evaluation scope, reproducible failure criteria, and evidence that no equivalent unmediated effect was exercised.
