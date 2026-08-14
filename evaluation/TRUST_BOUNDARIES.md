# Evaluation Trust-Boundary Services

This evaluation layer makes four external trust roles explicit:

- **CheckpointAnchor** — retains an immutable state-hash/generation anchor outside the mutable broker state being checked.
- **RevocationAuthority** — answers whether a lease has been revoked.
- **CompletionAnchor** — preserves forward-only completion/reconciliation state for an authorized action.
- **IdentityAuthority** — issues and verifies opaque identity assertions without exposing its signing secret to the evaluated caller.

`evaluation/trust_boundary.py` provides two reference realizations.

## LocalTrustBoundary

`LocalTrustBoundary` is a same-process implementation intended for deterministic tests. It demonstrates API semantics only. It is in the same memory and failure domain as the caller and therefore cannot support a strong independence claim.

## ProcessTrustBoundary

`ProcessTrustBoundary` places mutable trust state and its identity secret in a separate spawned process. The caller communicates through a narrow request/response pipe and does not hold direct references to the service dictionaries or secret.

This is useful for evaluating failure handling and for preventing ordinary in-process mutation from silently rewriting trust state. It is **not** an independent machine, HSM, cloud trust service, or separately administered failure domain. Passing tests with it is not A4 evidence.

## Fail-closed requirement

When the separate service is unavailable, the client raises `TrustBoundaryUnavailable`. Security-sensitive callers must treat that as an inability to establish authority/revocation/checkpoint/completion truth; they must not convert service failure into implicit approval.

## Completion transitions

The reference completion anchor accepts only:

```text
STARTED -> SUCCEEDED
STARTED -> FAILED_NO_EFFECT
STARTED -> OUTCOME_UNKNOWN
OUTCOME_UNKNOWN -> EFFECT_CONFIRMED
OUTCOME_UNKNOWN -> NO_EFFECT_CONFIRMED
```

Terminal states cannot transition backward, and `OUTCOME_UNKNOWN` never grants retry authority by itself.

A later empirical stage should replace or supplement the same-host process service with an independently administered process/service and record that topology in the evaluation manifest.
