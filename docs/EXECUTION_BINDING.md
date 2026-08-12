# AAB Authorization-to-Execution Binding

**Status:** Experimental reference hardening for AAB 0.4  
**Reference:** `reference/mediated_executor.py`

## Problem

An authorization system can correctly decide that an action is allowed and still fail if the subsequent tool invocation is not the exact action that was evaluated.

A weak path looks like:

```text
model request -> policy decision -> ALLOW -> caller constructs tool call -> side effect
```

The gap between `ALLOW` and the real invocation can permit target substitution, destination changes, credential changes, side-effect escalation, cost under-reporting, or ordinary adapter bugs.

## Required distinction

AAB therefore distinguishes:

- **requested action** — what the acting model says it wants to do;
- **effective action** — what the trusted tool adapter resolves and is actually prepared to do;
- **authorized action** — the effective action accepted by the AAB broker;
- **executed action** — the same prepared object passed to the adapter after authorization.

Authorization MUST be based on the effective action, not solely on model-declared fields.

## Reference flow

```text
MODEL / AGENT
     |
     v
requested action + adapter id
     |
     v
TRUSTED ADAPTER.prepare()
     |
     +-- resolves effective operation / target / destination
     +-- resolves credential reference / side-effect class
     +-- binds trusted cost
     |
     v
immutable PreparedAction
     |
     +-- canonical action hash
     |
     v
AAB BROKER.authorize(effective request, trusted cost)
     |
   DENY ---------------------> no execution
     |
   ALLOW
     |
     v
same PreparedAction object
     |
     v
TRUSTED ADAPTER.execute()
     |
     v
execution result + action hash
```

## Envelope invariants

A trusted adapter may resolve fields describing the real effect, but it MUST NOT silently change the authority/replay identity of the request.

The reference executor therefore binds these fields to the original request:

- request ID
- lease ID
- nonce
- monotonic sequence
- principal
- objective ID
- request timestamp

A mismatch fails before authorization.

## Effective-action fields

The adapter is permitted—and expected—to resolve the actual values that policy must evaluate, including:

- operation
- target
- destination
- credential reference
- side-effect class
- broker cost
- adapter-specific parameters

If resolution produces a value outside the authority lease, AAB denies the action even when the model's original request claimed an in-scope value.

## Execution binding hash

The reference computes a SHA-256 hash over canonical JSON containing:

- adapter identity
- effective broker request
- adapter parameters
- trusted cost

The caller-visible authorization receipt exposes this as `execution_binding_hash`. The same immutable `PreparedAction` is then passed to the adapter's `execute()` method.

This hash is an evidence binding. It does not itself create isolation or prove that the adapter implementation performed the claimed physical/network effect.

## Trust boundary

`MediatedExecutor` is an in-process reference mechanism. It assumes:

1. the adapter is part of the trusted enforcement plane;
2. the acting model cannot invoke the underlying tool or credential through another path;
3. adapter `prepare()` accurately resolves the effective action and cost;
4. adapter `execute()` operates on the prepared object it receives;
5. the authorization broker's state and decision are authoritative.

A production system SHOULD place preparation, authorization, and dispatch inside the same privileged mediation service or capability broker rather than returning a general-purpose `ALLOW` result to untrusted application code.

## Durable authorization

For real side effects, authorization state should be durable before the effect occurs. The AAB 0.4 durable broker follows this principle by persisting the authorization decision before returning successfully.

The reference `MediatedExecutor` accepts the broker protocol so tests can use the smaller broker. A production profile should combine execution binding with durable/transactional authorization state.

## Residual risks

This mechanism does not solve:

- an unmediated alternate tool or network path;
- a malicious/compromised trusted adapter;
- a compromised enforcement host;
- incorrect effective-target resolution by the adapter;
- side channels or equivalent effects omitted from the mediation topology;
- distributed transaction failure where an external side effect and accounting state require atomic coordination.

Those risks remain part of infrastructure hardening and architecture-specific adversarial evaluation.

## Evidence requirement

A strong deployment should be able to demonstrate, for each executed effect:

```text
model request
-> prepared effective action
-> action hash
-> authority lease
-> broker decision receipt
-> durable decision state
-> adapter dispatch
-> observed result
```

A successful tool call without that chain is not evidence of AAB-mediated execution.
