# AAB Authorization-to-Execution Binding

**Status:** Experimental reference hardening for AAB 0.4.1  
**References:** `reference/mediated_executor.py`, `reference/capability_contract.py`

## Problem

A correct policy decision is insufficient if the later tool call is not the exact action that was evaluated.

A weak flow is:

```text
model request -> ALLOW -> caller constructs/modifies invocation -> side effect
```

That gap can permit target, destination, credential, parameter, side-effect, or cost substitution after authorization.

A second problem is coarse authorization: even when operation and destination are allowed, malicious or unsafe parameters can make the allowed surface perform a different security-relevant effect.

## Required distinctions

AAB distinguishes:

- **requested action** — model-declared intent;
- **effective action** — adapter-resolved operation/effect;
- **contracted action** — effective action that satisfies the adapter capability contract;
- **authorized action** — contracted effective action accepted by AAB;
- **executed action** — the same immutable prepared descriptor dispatched after authorization.

Authorization MUST be based on the effective/contracted action, not solely on model-declared fields.

## Reference flow

```text
MODEL / AGENT
     |
     v
request + adapter ID
     |
     v
TRUSTED ADAPTER.prepare()
     |
     +-- resolve operation / target / destination
     +-- resolve credential / side-effect class
     +-- bind trusted cost
     +-- expose security effects
     |
     v
immutable PreparedAction
     |
     +-- capability-contract validation
     +-- canonical SHA-256 action hash
     |
     v
AAB BROKER.authorize(..., execution_binding_hash=hash)
     |
     +-- receipt chain covers exact action hash
     |
   DENY ----------------------> no execution
     |
   ALLOW + same binding hash
     |
     v
same PreparedAction
     |
     v
TRUSTED ADAPTER.execute()
```

## Bound authority/replay envelope

Adapter preparation may resolve effective effect fields but MUST NOT silently change:

- request ID;
- lease ID;
- nonce;
- monotonic sequence;
- principal;
- objective ID;
- request timestamp.

A mismatch fails before authorization.

## Effective-action fields

The adapter is expected to resolve the real values policy must evaluate:

- operation;
- target;
- effective destination;
- credential reference;
- side-effect class;
- broker cost;
- adapter parameters;
- security-relevant secondary effects.

If preparation resolves an out-of-scope value, AAB denies even if the original model request claimed an allowed value.

## Capability contracts

`reference/capability_contract.py` constrains an adapter operation more finely than destination/operation allowlists alone.

A contract can restrict:

- parameter keys;
- required parameters;
- explicit parameter value sets;
- effective destination;
- credential;
- redirects;
- filesystem paths;
- subprocess creation;
- secondary destinations.

The reference uses deny-by-default semantics for these declared effect classes.

This does not automatically understand arbitrary program semantics. The trusted adapter must accurately describe the effective operation and its security effects. Architecture-specific adapters can extend the contract model with additional effect classes where needed.

## Deep immutability

`PreparedAction` serializes the complete canonical descriptor at construction and returns detached copies of nested values. Caller or adapter mutation of source dictionaries/lists cannot change the already-hashed action.

The canonical hash covers:

- adapter identity;
- effective broker request;
- adapter parameters;
- trusted cost;
- declared security effects.

## Receipt binding

The action hash is passed into the broker before decision-receipt construction. The hash is therefore inside the broker's chained receipt.

The executor refuses dispatch when the returned receipt does not contain the exact same binding hash, even if the receipt otherwise says `ALLOW`.

This closes the earlier evidence gap where caller code appended an execution hash after receipt chaining.

## Durable authorization

For real effects, authorization state should be durable before the effect occurs. `DurableEnforcementBroker` persists the decision transition before returning successfully and serializes cooperating broker processes through a transaction lock.

A distributed deployment still has to reason about external side-effect/accounting atomicity. If the target system supports idempotency keys, transactions, or prepare/commit semantics, adapters should use them.

## Trust boundary

The reference assumes:

1. adapter preparation accurately reports the effective action;
2. adapter execution obeys the prepared object;
3. the model cannot invoke the underlying tool/credential through another route;
4. the broker's decision and durable state remain authoritative;
5. the capability contract enumerates the security-relevant effect dimensions needed for that adapter.

Production systems SHOULD keep preparation, contract evaluation, authorization, and dispatch inside the same privileged mediation service/capability broker.

## Residual risks

Execution binding does not solve:

- malicious/compromised trusted adapters;
- incorrect endpoint/effect resolution;
- unmodeled parameter semantics;
- alternate unmediated tool/network paths;
- compromised enforcement host;
- side channels/equivalent effects outside the topology;
- distributed transaction failure between broker persistence and a remote effect.

## Evidence requirement

A strong deployment should be able to reconstruct:

```text
model request
-> effective PreparedAction
-> capability contract
-> exact action hash
-> authority lease
-> chained broker decision containing that hash
-> durable decision state
-> adapter dispatch
-> observed result
```

A successful tool call without this chain is not evidence of AAB-mediated execution.
