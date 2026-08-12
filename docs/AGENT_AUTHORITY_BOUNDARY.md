# AMAS Agent Authority Boundary (AAB)

**Version:** 0.4-draft  
**Status:** Experimental normative extension with executable enforcement-path controls  
**Date:** 2026-08-12

## Purpose

AAB extends AMAS from contextual/memory authority to **action authority** for tool-using and autonomous agents.

AMAS Core answers: **which source is authoritative?**  
AAB answers: **is this proposed side effect authorized, and can the enforcement boundary prove that its own security state has not been reset or bypassed?**

AAB is designed on the assumption that capable agents can make mistakes, optimize around evaluators, discover unexpected capabilities, follow malicious retrieved instructions, or attempt to use reachable resources that were never authorized.

## Core invariants

1. **Capability is not authority.**
2. **Reachability is not authorization.**
3. **Data is not instruction.**
4. **Inference is not delegation.**
5. **Success does not widen scope.**
6. **No ambient authority.** Credentials, paths, tools, and privileges require explicit grants.
7. **Monotonic delegation.** Child authority may narrow but never silently widen parent authority.
8. **Fail closed.** Missing, ambiguous, expired, replayed, stale, unverifiable, or non-durable enforcement state is not authority.
9. **External enforcement.** The acting model is not the sole judge of its own authorization.
10. **Broker-owned security state.** Enforcement counters and replay state do not depend on agent assertions.
11. **Durable replay state.** Restarting the broker must not reset consumed nonces, request sequence, budgets, or receipt history.
12. **Rollback evidence.** Integrity-protected local state alone is insufficient; higher assurance requires an independently retained checkpoint capable of detecting restoration of an older valid state.
13. **Mediation completeness.** Every modeled path from an acting agent to a controlled side-effect sink must cross an enforcement broker.
14. **Decision receipts.** Authorization decisions must be auditable and tamper-evident.
15. **Evidence over assertion.** Higher containment claims require reproducible tests.

## 1. Authority leases

An action-capable runtime binds an agent to a time-bounded authority lease containing, at minimum:

- lease/policy identifiers
- issuer and principal identity
- objective identifiers
- operations, targets, and destinations
- credential references
- maximum side-effect class
- action/network/egress/time budgets
- delegation depth
- issuance and expiration times
- request freshness limits
- integrity/authentication metadata

Absence from an allowlist means denial.

AAB 0.3 introduced the signed reference lease in `schemas/signed_authority_lease.schema.json` and `reference/enforcement_broker.py`. The reference uses HMAC-SHA256 for standard-library portability; production signing authority should normally live outside the model execution environment and use deployment-appropriate key management.

## 2. Broker action requests

Before an external side effect, the broker receives a structured request containing:

- request identifier
- lease identifier
- unique nonce
- monotonic sequence number
- principal and objective
- operation, target, destination
- credential reference if any
- side-effect class
- delegation depth
- timestamp

The acting agent does not supply the authoritative cumulative counters used for its own authorization. The broker combines its persisted counters with trusted tool-adapter cost metadata before policy evaluation.

## 3. Enforcement order

### Envelope/state checks

The broker verifies:

1. lease authenticity
2. lease identifier binding
3. nonce uniqueness
4. monotonic sequence
5. request timestamp/freshness
6. broker-bound action cost
7. durable enforcement state validity
8. receipt-chain validity
9. optional external checkpoint consistency

### Policy checks

The policy gate then enforces:

1. policy freshness
2. principal binding
3. objective binding
4. operation scope
5. target scope
6. destination/network scope
7. credential scope
8. side-effect ceiling
9. action budget
10. network-call budget
11. egress-byte budget
12. wall-clock budget
13. delegation depth

## 4. Durable enforcement state — AAB 0.4

AAB 0.4 adds `reference/durable_broker.py`.

The durable state envelope persists:

- lease/policy identity
- state generation
- last accepted structural request sequence
- broker-owned cumulative usage
- consumed nonces
- complete decision-receipt chain
- receipt-chain tip
- state hash
- state integrity MAC

The reference persistence path uses write + file `fsync` + atomic replace and attempts directory `fsync` where supported.

**Critical execution rule:** a tool adapter must not interpret an authorization as executable until durable persistence succeeds. Persistence failure is therefore a fail-closed condition.

### Restart behavior

After restart, the broker restores replay state, cumulative budgets, sequence state, and receipt history. Restarting the process must not create fresh authority.

### Local integrity is not rollback protection

A valid MAC proves that a state object was produced by a holder of the integrity key. It does **not** prove that the object is the newest valid state. An attacker could restore an older, still-valid state file and thereby attempt to recover spent budget or previously consumed nonces.

AAB 0.4 therefore defines an independently signable checkpoint containing:

- lease/policy identity
- state generation
- state hash
- receipt count
- receipt-chain tip
- checkpoint timestamp

If restored broker state is older than the independently retained checkpoint, restoration fails closed with rollback evidence. If generation matches but state hash or receipt tip differs, restoration also fails closed.

The reference checkpoint is still HMAC-based and file-serializable. Production high-assurance deployments should anchor checkpoints in a different failure domain: remote append-only storage, a transparency service, hardware-backed journal, or equivalent.

See:

- `reference/durable_broker.py`
- `schemas/broker_state.schema.json`
- `schemas/broker_checkpoint.schema.json`
- `tests/test_durable_broker.py`

## 5. Mediation completeness / bypass testing — AAB 0.4

AAB cannot contain an agent if the agent can reach the same side effect through an unmediated route.

AAB 0.4 therefore introduces a structural mediation test. `reference/mediation_graph.py` models nodes such as:

- agents
- AAB brokers
- adapters/proxies
- side-effect sinks

For every modeled path from an `agent` node to a `side_effect` node, at least one `broker` node must occur before the side effect. A path without a broker is explicit bypass evidence.

This is a graph/topology proof over the declared architecture, not proof that the declaration is complete. Production evaluation must also enumerate real capabilities, file descriptors, subprocess paths, network routes, credential channels, RPC endpoints, plugins, and other mechanisms that could produce equivalent effects.

The initial corpus in `adversarial/bypass_topologies.json` covers:

- direct agent→effect bypass
- alternate adapter bypass
- indirect proxy bypass
- multi-agent bypass
- multiple side-effect sinks
- broker placement after the side effect
- mediated cycles
- unreachable sink configurations that do not constitute functional containment evidence

See `tests/test_mediation_graph.py`.

## 6. Side-effect classes

AAB retains the ordered ceiling:

`observe < simulate < reversible_write < persistent_write < privileged_change`

A request above the lease ceiling is denied.

## 7. Monotonic delegation

For parent policy `P` and child policy `C`:

- `C.objectives ⊆ P.objectives`
- `C.operations ⊆ P.operations`
- `C.targets ⊆ P.targets`
- `C.destinations ⊆ P.destinations`
- `C.credentials ⊆ P.credentials`
- `C.max_side_effect <= P.max_side_effect`
- every child budget `<=` the parent budget
- `C.expires_at <= P.expires_at`
- delegation depth strictly decreases
- `C.parent_policy_id == P.policy_id`

Any widening requires a new authority grant; it is not delegation. See `reference/delegation.py`.

## 8. Decision evidence

AAB decision receipts form a SHA-256 hash chain with monotonic receipt sequence and previous-receipt hash. The AAB 0.3 broker adds lease identity and authoritative broker usage. AAB 0.4 persists this chain and permits its tip to be externally checkpointed.

A hash chain detects mutation/reordering of observed entries but cannot alone prove the log was not truncated. Checkpoint anchoring is the complementary AAB 0.4 mechanism.

## 9. Threats constrained

AAB is designed to constrain or expose:

- target/objective substitution
- destination/network expansion
- ambient credential use
- privilege/side-effect expansion
- budget reset or expansion
- unauthorized delegation
- action laundering through model rationale
- success-derived scope expansion
- stale/replayed requests
- agent-supplied counter spoofing
- signed-lease mutation
- broker restart replay-state loss
- restoration of older authenticated broker state
- unmediated side-effect paths represented in the architecture graph

AAB cannot recover containment if the enforcement component, its signing keys, or an unmodeled equivalent side-effect path is compromised.

## 10. Reference architecture

```text
model / agent
     |
     v
structured request
     |
     v
+---------------------------+
| durable AAB broker        |
| - signed lease            |
| - replay state            |
| - broker counters         |
| - persisted receipts      |
| - checkpoint comparison   |
+-------------+-------------+
              |
              v
        policy gate
              |
              v
        tool adapter
              |
              v
       side-effect sink

independent checkpoint anchor <--- state hash / chain tip
```

The evaluated architecture must also show that there is no second path from the agent to the sink that avoids the broker.

## 11. Evidence boundary

AAB 0.4 materially strengthens the reference architecture but **does not establish A4 frontier-model containment**.

The new tests establish narrower propositions:

- security state survives broker restart
- replay protections survive broker restart
- authenticated state mutation is detected
- an independently retained checkpoint detects rollback to an older still-authenticated state
- modeled unmediated side-effect paths are detected

A4 remains an architecture-specific empirical claim requiring evidence that the evaluated model cannot discover or exercise an equivalent unmediated path in the real deployed environment.

## Reference artifacts

- `reference/authority_gate.py`
- `reference/enforcement_broker.py`
- `reference/durable_broker.py`
- `reference/mediation_graph.py`
- `reference/delegation.py`
- `reference/receipt_chain.py`
- `adversarial/aab_vectors.json`
- `adversarial/bypass_topologies.json`
- `schemas/signed_authority_lease.schema.json`
- `schemas/broker_action_request.schema.json`
- `schemas/broker_state.schema.json`
- `schemas/broker_checkpoint.schema.json`
- `schemas/decision_receipt.schema.json`
- `tests/test_enforcement_broker.py`
- `tests/test_durable_broker.py`
- `tests/test_mediation_graph.py`

## Status

AAB 0.4 is an experimental reference architecture with scoped policy enforcement, monotonic delegation, signed authority leases, replay controls, broker-owned cumulative accounting, durable authenticated enforcement state, rollback checkpoints, tamper-evident receipts, and structural bypass-path tests. Independent adversarial evaluation remains required.
