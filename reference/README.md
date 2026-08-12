# AMAS / AAB / AMCS Reference Implementations

**AMCS runtime:** 0.2.0  
**AMCS specification implemented:** v1.2.1 INTERNAL profile  
**AAB extension:** 0.4-draft reference components  
**Language:** Python 3.11+  
**Runtime dependencies:** Python standard library only

The `reference/` directory contains deliberately compact implementations of selected AMAS, AAB, and AMCS mechanisms. They are intended to make the specification falsifiable and reviewable. They are not production containment claims.

## AMCS — memory sealing and persistence

`amcs.py` converts supported chat transcripts into sealed, hash-verified memory-cell bundles with provenance and deterministic message identifiers.

```bash
python3 reference/amcs.py seal \
  --input examples/chat_minimal.json \
  --out-dir out \
  --cell-name MY_CELL

python3 reference/amcs.py verify \
  --cell out/MY_CELL.tar.gz
```

### AMCS 0.2.0 security boundary

The hardened runtime treats archive structure, attachment metadata, and output identifiers as security-sensitive inputs.

It therefore:

- restricts cell and supercell names to path-safe identifiers;
- builds cells in temporary directories inside the selected output root;
- refuses to seal a cell whose pre-seal verification fails;
- manually validates tar members instead of using unrestricted `extractall`;
- rejects absolute paths, `..` traversal, symlinks, hard links, devices, FIFOs, and unsupported archive members;
- enforces configurable archive member-count and expanded-size limits;
- requires message attachments to be relative to an explicit `--attachments-root`;
- rejects attachment paths that escape that root;
- verifies child cells before admitting them to a supercell;
- checks manifest hashes, missing files, and unlisted files during verification.

The `--odt` argument remains an explicit operator-selected evidence file and is not interpreted as message-supplied attachment metadata.

AMCS provides memory provenance, sealing, integrity, rehydration evidence, and persistence mechanics. It is **not** an action sandbox or model-containment layer.

## AAB policy gate

`authority_gate.py` evaluates a proposed action against an explicit authority policy. It does not execute the action.

```bash
python3 reference/authority_gate.py \
  --policy examples/authority_policy.json \
  --requests examples/action_requests.json
```

The reference gate covers:

- principal and objective binding;
- operation and target scope;
- destination/network scope;
- credential scope;
- side-effect ceilings;
- action/network/egress/time budgets;
- delegation depth;
- policy expiry;
- explicit operator escalation.

## AAB enforcement broker

`enforcement_broker.py` moves enforcement-critical state outside the acting model. It demonstrates:

- authenticated reference authority leases;
- nonce replay protection;
- monotonic request sequencing;
- request freshness checks;
- broker-owned cumulative usage accounting;
- broker-bound action cost metadata;
- chained authorization receipts.

The reference HMAC mechanism is intentionally compact. Production signing material must remain outside the model's trust boundary.

## Authorization-to-execution binding

`mediated_executor.py` addresses the gap between a correct `ALLOW` decision and the tool invocation that actually occurs.

A trusted adapter first prepares the **effective** action—including the real operation, target, destination, credential reference, side-effect class, adapter parameters, and broker cost. AAB authorizes those effective fields, not merely the model's claimed fields. Only an `ALLOW` decision permits the same immutable `PreparedAction` object to reach the adapter's `execute()` method.

The prepared descriptor receives a canonical SHA-256 action hash that is exposed as `execution_binding_hash` in the caller-visible authorization evidence.

The reference executor also prevents adapter preparation from silently changing the request's lease ID, nonce, sequence, principal, objective ID, request ID, or timestamp.

See [`../docs/EXECUTION_BINDING.md`](../docs/EXECUTION_BINDING.md).

This is still an in-process reference. A production system must prevent direct access to the underlying adapter/tool and should combine execution binding with durable, transactional authorization state.

## Durable enforcement state

`durable_broker.py` adds AAB 0.4 reference mechanisms for:

- persisted replay, sequence, usage, and receipt state;
- authenticated state envelopes;
- generation counters;
- atomic replacement with `fsync`-based persistence;
- restart recovery;
- independently signable checkpoints;
- detection of restoration behind a retained checkpoint.

This is a reference persistence design, not a substitute for a transactional authorization service, HSM, remote transparency log, or equivalent production infrastructure.

## Monotonic delegation

`delegation.py` verifies that delegated child authority is a subset of parent authority across objectives, operations, targets, destinations, credentials, side effects, budgets, expiry, and delegation depth.

The schema surface includes both:

- `schemas/child_authority_policy.schema.json`; and
- `schemas/signed_child_authority_lease.schema.json`.

A child authority grant may narrow authority. Widening requires a new authority grant rather than delegation.

## Mediation graph

`mediation_graph.py` checks a declared topology for broker bypass.

The verifier removes broker nodes and uses deterministic breadth-first reachability. If any modeled agent can still reach a side-effect sink, the topology fails and a shortest bypass witness is returned.

This avoids enumerating every simple path and makes the structural test scale with graph size. It proves a property of the **declared graph only**; it does not prove that a deployment has enumerated every equivalent-effect path.

## Receipt chain

`receipt_chain.py` creates and verifies SHA-256-linked authorization receipts. Mutation and reordering inside an observed chain are detectable. A hash chain alone does not prevent complete chain truncation; stronger deployments require an independent anchor.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

The test suite includes:

- policy and adversarial AAB vectors;
- monotonic delegation checks;
- enforcement-broker replay/budget tests;
- authorization-to-execution binding tests;
- durable restart/rollback tests;
- mediation/bypass topology tests;
- AMCS archive/filesystem boundary tests;
- Draft 2020-12 JSON Schema validation.

CI additionally performs an AMCS seal→verify round trip.

## Separation of responsibilities

- **AMAS Core** — contextual and memory authority doctrine.
- **Runtime Binding** — lifecycle mechanics implementing AMAS governance.
- **AMCS** — sealing, provenance, integrity, and memory persistence.
- **AAB policy/enforcement components** — external action authorization and enforcement-state integrity.
- **AAB mediated execution** — binding the authorized effective action to trusted adapter dispatch.

Production AAB deployments still require complete mediation of relevant side effects, process isolation, network egress controls, least-privilege identities, secret isolation, controlled subprocess/plugin paths, transactional authorization state, independently protected evidence, and adversarial evaluation.

## Evidence boundary

Reference code demonstrates specific mechanisms under stated assumptions. It does **not** establish certified production conformance, complete side-effect mediation, or frontier-model containment.
