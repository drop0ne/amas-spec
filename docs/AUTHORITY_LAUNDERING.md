# Automated Authority Laundering

## Definition

**Automated authority laundering** is the process by which consequential decisions or side effects are made through an AI system in a way that obscures who authorized them, at what authority level, for what scope, and through what chain of delegation or transition.

The system converts ambiguous, unauthorized, inferred, retrieved, or merely reachable material into apparently legitimate behavior even though the required authority was never actually granted.

## Common mechanisms

### Data becomes instruction
A retrieved document or tool result contains imperative language and is treated as a directive.

**AMAS response:** semantic role is independent of tier. Evidence/observation/inference does not become a directive through wording.

### Inference becomes fact or delegation
One model's synthesis is consumed downstream without retaining its inferential origin.

**AMAS response:** inference is Tier 3 and cannot directly authorize behavior.

### Self-asserted supersession
A newer same-tier object claims that it supersedes another and the runtime accepts the claim because the object contains a `supersedes` field.

**AMAS response:** provenance must be traceable and a trusted authority context outside the disputed object must verify that the issuer possessed authority over the superseded tier/scope. Metadata is not self-authentication.

### Reachability becomes permission
An agent discovers a host, credential, filesystem path, subprocess, plugin, or other capability and treats availability as authority.

**AAB response:** explicit leases, capability contracts, effective-action resolution, and external enforcement. Reachability is not authorization.

### “Authorize A, execute B”
A policy gate approves one request but later code constructs a materially different effect.

**AAB response:** the trusted adapter prepares the effective immutable action first, and its exact hash is included in the broker's chained authorization receipt.

### Authorization becomes assumed completion
An effect may occur but the response is lost. A caller treats the exception as proof of failure and retries, potentially duplicating the side effect.

**AAB response:** authorization and completion are different facts. The reference records `STARTED` before dispatch and then `SUCCEEDED` or `OUTCOME_UNKNOWN`. Uncertainty is not an automatic retry signal.

### Durable state silently restores authority
Restart, rollback, concurrency, or history deletion causes spent replay/budget authority to appear available again.

**AAB response:** transaction-safe durable state, ancestry/checkpoints, and finite explicit epochs rather than silent history discard.

## Why provenance alone is insufficient

A provenance field can describe a claim while still being self-authored by an unauthorized object. Likewise, a decision receipt can record a policy decision while leaving the actual dispatch or completion ambiguous.

Anti-laundering therefore requires several layers:

- **classification** — tier + semantic role;
- **admission** — complete machine contract before authority decisions;
- **transition authorization** — trusted verification for escalation/supersession/delegation;
- **effective-action mediation** — evaluate what will actually happen, not only what the model said;
- **transactional state** — replay/budgets cannot be reset or double spent;
- **execution binding** — exact prepared action tied to authorization evidence;
- **completion integrity** — uncertainty after dispatch remains visible;
- **portable encoding** — independent implementations cannot reinterpret security values differently.

## Runtime-binding seam

Runtime mechanics are part of the anti-laundering control surface because they expose:

- which canonical root activated;
- which ledger was writable;
- whether mutation/repair/export was authorized;
- which conflict rule resolved an authority dispute;
- whether supersession authority was externally verified;
- what lease/policy/action binding governed a side effect;
- what replay/budget state was authoritative;
- whether an effect is `SUCCEEDED` or `OUTCOME_UNKNOWN`;
- what state/checkpoint/receipt evidence is available to an operator.

Without this seam, provenance can exist on paper while operational authority disappears into middleware.

## Residual risk

AMAS/AAB cannot eliminate authority laundering caused by:

- compromise of a legitimately trusted authority or enforcement service;
- malicious principals that genuinely possess the relevant authority;
- incorrect Memory Object segmentation;
- trusted adapters that misdescribe effects;
- unmodeled equivalent-effect paths;
- operators who ignore or suppress verification evidence;
- remote systems that cannot support required reconciliation/idempotency semantics.

The architecture's objective is not to make authority infallible. It is to make authority **explicit, bounded, machine-checkable, and reconstructable instead of inferred from model behavior after the fact.**
