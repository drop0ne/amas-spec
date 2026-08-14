# AAB Completion Integrity

**Status:** reference hardening rule for the AAB 0.4.1 line.

## Authorization is not completion

An `ALLOW` receipt establishes that one exact prepared action was authorized. It does **not** establish that the side effect completed, failed before effect, or did not occur.

A trusted adapter may cross an external side-effect boundary and then lose its response, raise an exception, crash, or return a result that cannot be serialized. Treating those cases as "nothing happened" creates an unsafe retry path.

## Reference completion states

`reference/mediated_executor.py` therefore maintains a transactional completion journal keyed by:

- the chained authorization `receipt_hash`; and
- the exact `PreparedAction.action_hash`.

The deterministic execution ID is the Canonical JSON v1 SHA-256 of those two hashes.

The journal uses these states:

- `STARTED` — written before adapter dispatch;
- `SUCCEEDED` — the adapter call returned; the external effect is considered completed even if its returned value cannot be serialized for the caller;
- `OUTCOME_UNKNOWN` — dispatch occurred but completion cannot be established.

A persisted `STARTED` record observed after restart is interpreted as `OUTCOME_UNKNOWN`.

## Fail-closed rules

1. If the completion journal cannot write `STARTED`, the adapter MUST NOT be called.
2. Once dispatch occurs, an adapter exception MUST NOT be reported as a clean pre-effect failure.
3. A finalization/storage failure after dispatch MUST be surfaced as `OUTCOME_UNKNOWN`.
4. `OUTCOME_UNKNOWN` MUST NOT be automatically retried merely because the caller did not receive a successful result.
5. Idempotent/reconcilable adapters SHOULD provide an external idempotency or operation identifier derived from the execution ID.
6. Deployments requiring crash durability MUST use a filesystem-backed completion journal in an independent trusted persistence domain; the in-memory test mode is not durable evidence.

## Evidence boundary

The reference journal narrows one important authorization-to-completion ambiguity. It does not create a distributed transaction across arbitrary external systems and does not prove that an adapter or remote service implements idempotent exactly-once semantics.

A production deployment should pair this mechanism with service-specific reconciliation, idempotency keys, effect receipts, or transactional APIs where available.
