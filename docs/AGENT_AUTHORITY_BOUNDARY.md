# AMAS Agent Authority Boundary (AAB)

**Version:** 0.4.1-draft  
**Status:** Experimental normative extension with executable enforcement-path hardening  
**Date:** 2026-08-12

## Purpose

AAB extends AMAS from contextual/memory authority to external action authority for tool-using and autonomous agents.

AMAS Core asks **which contextual object has authority?** AAB asks **does this principal possess authority for this exact effective side effect, and can the enforcement path preserve evidence that authorization state was neither widened, replayed, reset, forked, nor bypassed?**

AAB assumes capable agents can misunderstand instructions, follow hostile retrieved data, optimize around an evaluator, discover unintended capabilities, or attempt to use reachable resources that were never delegated.

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
13. Newer durable state must descend from the checkpointed lineage, not merely carry a larger counter.
14. Authorization binds the exact effective prepared action, not merely the model's claimed intent.
15. Security-relevant adapter parameters and secondary effects are part of authority.
16. Every modeled path from an acting agent to a controlled side-effect sink must cross the enforcement boundary.
17. Decisions are auditable and tamper-evident.
18. Higher containment claims require reproducible architecture-specific evidence.

## 1. Authority leases

An action-capable runtime binds a principal to an authenticated lease. The reference lease carries:

- `lease_version`;
- lease/policy identifiers;
- issuer and `key_id`;
- principal identity;
- issue time and `not_before`;
- policy expiry;
- maximum request age;
- objectives, operations, targets, destinations, credentials;
- allowed capability-contract identifiers;
- side-effect ceiling;
- action/network/egress/time budgets;
- delegation depth;
- integrity/authentication metadata.

Absence from an allowlist means denial.

The reference uses HMAC-SHA256 for compact standard-library examples. Production signing keys should be isolated from the acting model and selected for the deployment trust architecture.

### Revocation

Expiry is not sufficient for emergency containment. The reference broker accepts an external `revocation_checker(lease_id)` and fails closed when a lease is revoked. The simple in-memory `RevocationRegistry` exists for tests only; production revocation state must be authenticated, durable, and outside the model's control.

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

`reference/capability_contract.py` adds adapter-specific constraints for:

- allowed/required parameter keys;
- parameter value allowlists;
- effective destinations;
- credentials;
- redirect chains;
- filesystem paths;
- subprocess effects;
- secondary network destinations.

An allowed endpoint or operation does not imply that every parameterization of it is authorized.

The trusted adapter is part of the enforcement plane. AAB cannot protect against an adapter that lies about the effect it will execute.

## 3. Authorization-to-execution binding

`reference/mediated_executor.py` computes a SHA-256 hash over the canonical immutable prepared action, including security effects and trusted cost.

That `execution_binding_hash` is passed into the broker **before** the broker creates its decision receipt. The broker's receipt chain therefore covers the exact prepared-action hash.

Execution is released only when:

1. preparation succeeds;
2. any configured capability contract succeeds;
3. AAB policy evaluation returns `ALLOW`;
4. the chained broker receipt contains the same `execution_binding_hash`; and
5. the same immutable `PreparedAction` is passed to the registered trusted adapter.

A general-purpose `ALLOW` result returned to untrusted application code is weaker than this design.

## 4. Replay and cumulative budgets

The broker verifies:

1. lease authenticity and validity window;
2. revocation state;
3. lease identifier binding;
4. nonce format and uniqueness;
5. exact monotonic request sequence;
6. request freshness/future skew;
7. capability-contract scope;
8. trusted adapter cost;
9. policy scope and side-effect ceiling;
10. cumulative broker-owned budgets.

The acting agent does not supply the authoritative cumulative counters used for its own authorization.

Structurally valid requests consume replay identity even when policy denies them, preventing a denied envelope from later being replayed as new.

## 5. Durable enforcement state

AAB 0.4.1 uses durable-state format version 2 in `reference/durable_broker.py`.

Persisted state includes:

- lease/policy identity;
- generation;
- `previous_state_hash`;
- explicit ancestor-state hashes;
- last accepted structural request sequence;
- cumulative usage;
- consumed nonces;
- complete decision-receipt chain;
- receipt-chain tip;
- state hash and integrity MAC.

### Transaction serialization

A local SQLite sidecar is used only as a compact reference transaction lock. Every authorization performs `BEGIN IMMEDIATE`, reloads the newest authenticated JSON state while holding the lock, evaluates against that state, persists the next state, and only then releases the transaction.

This removes the earlier stale-process double-spend condition in which two broker instances could both authorize against the same counters/sequence snapshot.

A production system may instead use a transactional database, single-writer service, consensus-backed store, or other mechanism appropriate to its threat model.

### Persistence-before-effect

A real side effect MUST NOT be interpreted as executable until the durable authorization transition succeeds. Persistence failure is fail-closed. The reference broker poisons an instance after a persistence failure so callers cannot continue using uncertain in-memory state.

## 6. Rollback and state ancestry

A valid MAC proves integrity/authorship under a key; it does not prove freshness.

AAB therefore supports independently retained checkpoints containing the state generation, state hash, receipt count, and receipt-chain tip.

AAB 0.4.1 strengthens this from generation-only comparison to explicit ancestry:

- older state than the checkpoint fails;
- equal-generation state must exactly match the checkpoint;
- a higher-generation state is accepted only if the checkpointed state hash appears at the expected ancestry position and the receipt chain extends the checkpoint tip.

This detects a higher-generation divergent fork under the modeled state format.

The checkpoint must remain in an independent failure domain for meaningful rollback resistance.

## 7. Monotonic delegation

For parent policy `P` and child policy `C`:

- `C.objectives ⊆ P.objectives`;
- `C.operations ⊆ P.operations`;
- `C.targets ⊆ P.targets`;
- `C.destinations ⊆ P.destinations`;
- `C.credentials ⊆ P.credentials`;
- `C.capability_contracts ⊆ P.capability_contracts`;
- child side-effect ceiling ≤ parent ceiling;
- every child budget ≤ corresponding parent budget;
- child expiry ≤ parent expiry;
- delegation depth strictly decreases;
- parent lineage is explicit.

Any widening requires a new authority grant; it is not delegation.

## 8. Mediation completeness

A policy engine cannot contain an agent that can produce the same effect by avoiding the engine.

`reference/mediation_graph.py` treats bypass as a reachability property: removing broker nodes must disconnect every modeled agent from every modeled side-effect sink. A shortest bypass witness is returned when this fails.

This is proof only over the declared topology. A real evaluation must enumerate actual:

- tool adapters;
- network routes and redirects;
- credential paths;
- files/file descriptors;
- subprocess and plugin mechanisms;
- RPC/service channels;
- secondary/equivalent-effect paths;
- collaborating agents.

## 9. Decision evidence

Decision receipts are SHA-256 chained with monotonic receipt sequence and previous-receipt hash. Broker receipts can include:

- exact model/broker envelope hash;
- policy-evaluation request hash;
- policy hash;
- lease identity;
- authoritative usage;
- exact execution-binding hash.

Hash chaining detects mutation/reordering of observed records. It does not alone prove that an unanchored chain was not truncated. Durable state and external checkpoints provide complementary evidence.

## 10. Threats constrained

The reference architecture is designed to constrain or expose:

- target/objective substitution;
- destination expansion;
- ambient credential use;
- side-effect/privilege expansion;
- parameter smuggling through an otherwise allowed operation;
- unapproved redirects, filesystem/subprocess effects, and secondary destinations;
- budget reset or expansion;
- unauthorized delegation;
- action laundering through model rationale;
- success-derived scope expansion;
- stale/replayed requests;
- agent-supplied counter spoofing;
- lease tampering, premature use, or modeled revocation;
- broker-restart replay-state loss;
- stale multi-process authorization state;
- restoration of older authenticated state;
- divergent state lineage relative to a checkpoint;
- mutation of the exact action authorized in the decision receipt;
- modeled unmediated side-effect paths.

## 11. Residual trust and failure boundary

AAB does not recover containment if any of the following are compromised or omitted:

- the enforcement host;
- signing/revocation/checkpoint keys or services;
- trusted adapter correctness;
- operating-system/hypervisor isolation;
- effective endpoint resolution;
- an unmodeled equivalent side-effect path;
- conventional infrastructure vulnerabilities that permit bypass of mediation.

The reference implementation is intentionally small enough to inspect; it is not a production security appliance.

## 12. Evidence boundary

AAB 0.4.1 materially strengthens the executable reference mechanisms but **does not establish A4 frontier-model containment**.

Current automated tests establish narrower propositions about the reference code: scope enforcement, parameter/effect contracts, binding hashes, replay controls, transactional state serialization, delegation monotonicity, ancestry/checkpoint behavior, and modeled bypass detection.

A4 remains an architecture-specific empirical claim requiring a real mediated environment, a capable adversarial agent, complete evaluation scope, reproducible failure criteria, and evidence that no equivalent unmediated effect was exercised.
