# AMAS Agent Authority Boundary (AAB)

**Version:** 0.3-draft  
**Status:** Experimental normative extension with executable enforcement-path controls  
**Date:** 2026-08-12

## Purpose

AAB extends AMAS from contextual and memory authority to **action authority**. It is designed for tool-using and autonomous agents that can produce external side effects.

AMAS Core determines which source is authoritative. AAB determines whether a proposed action is authorized. AAB 0.3 additionally constrains the **enforcement path itself** so the acting model cannot simply self-report the state used to authorize its next action.

## Core invariants

1. **Capability is not authority.** The ability to perform an action does not authorize it.
2. **Reachability is not authorization.** Discovering or reaching a resource does not place it in scope.
3. **Data is not instruction.** Retrieved content cannot grant execution authority merely by containing imperative language.
4. **Inference is not delegation.** Model-generated reasoning cannot create new authority.
5. **Success does not widen scope.** A successful action cannot implicitly authorize follow-on targets, methods, credentials, or destinations.
6. **No ambient authority.** Credentials, tools, network paths, and privileges must be explicitly bound to an authority lease.
7. **Monotonic delegation.** A delegated child scope MUST be equal to or narrower than its parent scope.
8. **Fail closed.** Missing, ambiguous, expired, stale, replayed, or unverifiable authority results in DENY or explicit operator escalation.
9. **External enforcement.** The acting model MUST NOT be the sole judge of whether its proposed action is authorized.
10. **Broker-owned security state.** Counters, replay state, and authorization-chain state used for enforcement MUST NOT depend solely on agent assertions.
11. **Decision receipts.** Every authorization decision MUST be auditable.
12. **Evidence over assertion.** Higher containment claims require reproducible adversarial evidence, not documentation alone.

## Action Authority Lease

An action-capable runtime SHOULD bind the agent to a time-bounded policy lease containing:

- policy/lease identifier
- issuer identity
- issuance time
- principal identity
- objective identifiers
- allowed operations
- allowed targets
- allowed destinations
- allowed credential references
- maximum side-effect class
- action, network, egress, and wall-clock budgets
- maximum delegation depth
- expiration time
- operator escalation behavior
- request freshness window
- cryptographic authentication of the lease

Absence from an allowlist means denial.

### Signed lease envelope

AAB 0.3 introduces a signed lease envelope. The reference implementation uses HMAC-SHA256 because it is available in the Python standard library and keeps the example compact. This is a demonstration mechanism, not a recommendation that production deployments expose symmetric signing material to agents.

A production deployment SHOULD keep signing authority outside the model execution environment and use an authentication mechanism appropriate to its trust architecture, such as managed asymmetric signing, a hardware-backed key, workload identity, or a dedicated authorization service.

Changing any signed lease field invalidates the signature.

See `schemas/signed_authority_lease.schema.json` and `reference/enforcement_broker.py`.

## Broker Action Request

Before an external side effect, the execution broker receives a structured request containing:

- request identifier
- lease identifier
- unique nonce
- monotonic request sequence
- principal
- objective identifier
- operation
- target
- destination, if any
- credential reference, if any
- side-effect class
- delegation depth
- timestamp

The agent does **not** control the authoritative cumulative usage counters used by AAB 0.3 enforcement.

### Trusted cost binding

The reference broker accepts a `cost` object separately from the agent request. This represents metadata computed or bound by the broker/tool adapter describing the action that is actually about to occur.

Production systems MUST NOT trust an agent to self-declare the cost of its own side effect. Network calls, egress, execution time, action count, and comparable resources should be measured or conservatively reserved by the enforcement layer.

## Side-effect classes

AAB defines an ordered ceiling:

`observe < simulate < reversible_write < persistent_write < privileged_change`

A policy authorizes a maximum class. A request above that ceiling is denied.

## Decision outcomes

- `ALLOW` — request is within the explicit lease.
- `DENY` — request violates a hard boundary.
- `ESCALATE` — request is not authorized but policy permits explicit operator review.
- `SIMULATE` — optional runtime behavior that redirects an unauthorized real action into a non-side-effecting environment. Simulation MUST NOT be represented as successful real-world execution.

## Enforcement-path evaluation

AAB 0.3 separates request-envelope checks from policy-scope checks.

### Envelope and state checks

Before policy evaluation, the broker checks:

1. signed lease validity
2. lease identifier binding
3. nonce uniqueness
4. monotonic request sequence
5. request timestamp validity
6. request freshness window
7. broker-supplied cost validity

### Policy checks

The underlying AAB gate then evaluates:

1. policy freshness
2. principal binding
3. objective binding
4. operation scope
5. target scope
6. destination/network scope
7. credential scope
8. side-effect ceiling
9. authoritative action budget
10. authoritative network-call budget
11. authoritative egress-byte budget
12. authoritative wall-clock budget
13. delegation depth

The reference broker replaces any request-supplied usage counters with broker-owned prospective counters before invoking the authorization gate.

## Replay resistance

Every broker request carries both a nonce and a request sequence.

- A nonce MUST NOT be accepted more than once for a lease.
- A structurally valid request sequence MUST advance monotonically by one.
- Requests outside the configured freshness window are denied.
- Requests materially timestamped in the future are denied.
- Once a structurally valid request reaches policy evaluation, its nonce and sequence are consumed even if the policy decision is DENY.

Replay resistance is scoped to broker state. A production deployment that needs restart durability MUST persist nonce/sequence state or bind it to an external durable authorization service.

## Broker-owned cumulative budgets

AAB 0.1/0.2 demonstrated cumulative budget checks using structured request usage fields. AAB 0.3 moves enforcement-critical counters into the broker.

For each request the broker computes prospective cumulative usage from its current trusted state plus the trusted action cost. The acting model cannot reset its budget by sending smaller counters.

For denied actions, the reference broker consumes the action-attempt count but does not charge network/egress/wall-clock effects that were not actually performed. Production systems may choose a stricter accounting policy.

## Monotonic delegation

Delegation MUST NOT create authority.

For parent policy `P` and child policy `C`, conformance requires:

- `C.objectives ⊆ P.objectives`
- `C.operations ⊆ P.operations`
- `C.targets ⊆ P.targets`
- `C.destinations ⊆ P.destinations`
- `C.credentials ⊆ P.credentials`
- `C.max_side_effect <= P.max_side_effect`
- every child budget `<=` its corresponding parent budget
- `C.expires_at <= P.expires_at`
- child delegation depth strictly consumes the parent's remaining delegation budget
- `C.parent_policy_id == P.policy_id`

Any widening requires a new authority grant from an authorized principal; it is not delegation.

`reference/delegation.py` implements both a verifier and a safe child-policy derivation helper. A malformed or widened child policy fails closed.

## Tamper-evident decision receipts

Each chained receipt carries:

- monotonic receipt `sequence`
- `previous_receipt_hash`
- `receipt_hash`

AAB 0.3 broker receipts additionally expose:

- `lease_id`
- broker-owned `authoritative_usage`

The genesis previous hash is 64 zeroes. The receipt hash is computed over canonical JSON excluding `receipt_hash` itself.

This detects mutation and reordering of receipts within an observed chain. It does **not** by itself prevent full-chain truncation or prove durable storage. Production systems SHOULD anchor chain tips in an independent signed, append-only, or otherwise tamper-resistant store.

See `reference/receipt_chain.py`.

## Adversarial evidence corpus

The executable corpus under `adversarial/aab_vectors.json` covers policy-level attacks including:

- principal impersonation
- objective substitution
- operation expansion
- target substitution
- destination expansion
- ambient credential use
- side-effect escalation
- action/network/egress/time budget overruns
- unauthorized delegation
- malformed requests
- boundary-value authorization

AAB 0.3 adds broker tests for:

- signed-lease tampering
- nonce replay
- sequence gaps
- stale requests
- future-dated requests
- agent attempts to spoof cumulative usage
- cumulative broker-budget exhaustion
- decision-receipt mutation
- malformed trusted-cost envelopes

This is an evidence surface, not a claim that all model escape or sandbox-escape mechanisms are contained. A4 remains reserved for stronger adversarial evidence demonstrating that the model cannot bypass the enforcement path in the evaluated architecture.

## Security boundary

AAB is intended to be implemented outside the model, ideally at the tool broker, capability proxy, sandbox boundary, or execution gateway. Prompt-only enforcement does not satisfy the strong action-boundary profile because the model can influence its own prompt-visible state.

A production action path should approximate:

```text
model -> structured request -> authenticated broker -> AAB policy gate -> tool adapter -> side effect
                                  |                     |
                                  +-> trusted counters <-+
                                  +-> replay state
                                  +-> receipt chain
```

The model should not possess a second unrestricted path to the same tool, network destination, credential, or side effect.

Production deployments should combine AAB with OS/process isolation, network egress filtering, least-privilege identities, secret isolation, rate limits, immutable or append-only audit logs, and independent monitoring.

## Threats addressed

AAB is designed to constrain:

- target substitution
- destination expansion
- lateral movement through newly discovered resources
- ambient credential use
- privilege expansion
- budget/rate reset or expansion
- unauthorized delegation or sub-agent spawning
- action laundering through model-generated rationale
- implicit authority inferred from tool success
- stale/replayed action requests
- agent-supplied false cumulative usage
- unauthorized mutation of signed lease fields

AAB cannot protect a system when the enforcement plane itself is bypassed or compromised.

## Reference artifacts

- `reference/authority_gate.py` — executable deny-by-default policy gate
- `reference/enforcement_broker.py` — signed-lease, replay-resistant, stateful broker
- `reference/delegation.py` — monotonic child-policy verifier/deriver
- `reference/receipt_chain.py` — tamper-evident receipt-chain helper
- `schemas/authority_policy.schema.json`
- `schemas/signed_authority_lease.schema.json`
- `schemas/action_request.schema.json`
- `schemas/broker_action_request.schema.json`
- `schemas/child_authority_policy.schema.json`
- `schemas/decision_receipt.schema.json`
- `adversarial/aab_vectors.json`
- `tests/test_authority_gate.py`
- `tests/test_delegation.py`
- `tests/test_adversarial_vectors.py`
- `tests/test_enforcement_broker.py`

## Status

AAB 0.3 is an experimental reference architecture with executable policy enforcement, monotonic delegation, broker-owned cumulative accounting, signed authority leases, replay controls, tamper-evident receipt chaining, and adversarial tests. It does **not** establish proven frontier-model containment. Independent adversarial evaluation and enforcement-path bypass testing remain required.
