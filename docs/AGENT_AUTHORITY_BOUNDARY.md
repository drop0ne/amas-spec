# AMAS Agent Authority Boundary (AAB)

**Version:** 0.1-draft  
**Status:** Experimental normative extension  
**Date:** 2026-08-12

## Purpose

AAB extends AMAS from contextual and memory authority to **action authority**. It is designed for tool-using and autonomous agents that can produce external side effects.

AMAS Core determines which source is authoritative. AAB determines whether a proposed action is authorized.

## Core invariants

1. **Capability is not authority.** The ability to perform an action does not authorize it.
2. **Reachability is not authorization.** Discovering or reaching a resource does not place it in scope.
3. **Data is not instruction.** Retrieved content cannot grant execution authority merely by containing imperative language.
4. **Inference is not delegation.** Model-generated reasoning cannot create new authority.
5. **Success does not widen scope.** A successful action cannot implicitly authorize follow-on targets, methods, credentials, or destinations.
6. **No ambient authority.** Credentials, tools, network paths, and privileges must be explicitly bound to an authority lease.
7. **Monotonic delegation.** A delegated child scope MUST be equal to or narrower than its parent scope.
8. **Fail closed.** Missing, ambiguous, expired, or unverifiable authority results in DENY or explicit operator escalation.
9. **External enforcement.** The acting model MUST NOT be the sole judge of whether its proposed action is authorized.
10. **Decision receipts.** Every authorization decision MUST be auditable.

## Action Authority Lease

An action-capable runtime SHOULD bind the agent to a time-bounded policy lease containing:

- policy/lease identifier
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

Absence from an allowlist means denial.

## Action Request

Before an external side effect, the agent submits a structured request containing:

- request identifier
- principal
- objective identifier
- operation
- target
- destination, if any
- credential reference, if any
- side-effect class
- cumulative budget counters
- delegation depth
- timestamp

The enforcement plane evaluates the request **before** tool execution.

## Side-effect classes

AAB defines an ordered ceiling:

`observe < simulate < reversible_write < persistent_write < privileged_change`

A policy authorizes a maximum class. A request above that ceiling is denied.

## Decision outcomes

- `ALLOW` — request is within the explicit lease.
- `DENY` — request violates a hard boundary.
- `ESCALATE` — request is not authorized but policy permits explicit operator review.
- `SIMULATE` — optional runtime behavior that redirects an unauthorized real action into a non-side-effecting environment. Simulation MUST NOT be represented as successful real-world execution.

## Evaluation order

An implementation MUST reject or escalate on the first failed hard boundary:

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

The reference implementation returns a machine-readable receipt identifying the failed boundary.

## Delegation

Delegation MUST NOT create authority.

For parent policy `P` and child policy `C`, conformance requires:

- `C.operations ⊆ P.operations`
- `C.targets ⊆ P.targets`
- `C.destinations ⊆ P.destinations`
- `C.credentials ⊆ P.credentials`
- `C.max_side_effect <= P.max_side_effect`
- every child budget `<=` its corresponding parent budget
- `C.expires_at <= P.expires_at`
- child delegation depth strictly consumes the parent's remaining delegation budget

Any widening requires a new authority grant from an authorized principal; it is not delegation.

## Security boundary

AAB is intended to be implemented outside the model, ideally at the tool broker, capability proxy, sandbox boundary, or execution gateway. Prompt-only enforcement does not satisfy the strong action-boundary profile because the model can influence its own prompt-visible state.

Production deployments should combine AAB with OS/process isolation, network egress filtering, least-privilege identities, secret isolation, rate limits, immutable or append-only audit logs, and independent monitoring.

## Threats addressed

AAB is designed to constrain:

- target substitution
- destination expansion
- lateral movement through newly discovered resources
- ambient credential use
- privilege expansion
- budget/rate expansion
- unauthorized delegation or sub-agent spawning
- action laundering through model-generated rationale
- implicit authority inferred from tool success

AAB cannot protect a system when the enforcement plane itself is bypassed or compromised.

## Reference artifacts

- `reference/authority_gate.py` — executable deny-by-default reference gate
- `schemas/authority_policy.schema.json`
- `schemas/action_request.schema.json`
- `schemas/decision_receipt.schema.json`
- `examples/authority_policy.json`
- `examples/action_requests.json`
- `tests/test_authority_gate.py`

## Status

AAB 0.1 is an experimental extension. It defines a falsifiable enforcement surface, not a claim of proven frontier-model containment. Independent adversarial evaluation remains required.
