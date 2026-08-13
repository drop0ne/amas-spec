# Reference Implementations

The code in this directory is executable **reference material**, not a production security appliance. Each module demonstrates a bounded property of AMAS, AAB, or AMCS and is intentionally small enough for review.

## Current reference surfaces

### `conflict_resolution.py`
Implements AMAS 2.0-draft pairwise arbitration with:
- semantic-role admissibility (`DIRECTIVE` vs data/observation/inference);
- tier precedence;
- explicit supersession;
- structural `scope_path` specificity;
- recency;
- unique fail-closed `HALT_ESCALATE` fallback.

### `authority_gate.py`
Stateless deny-by-default AAB policy evaluation over:
- principal/objective/operation/target;
- destination and credential scope;
- capability-contract identity;
- side-effect ceiling;
- cumulative usage presented by a trusted broker;
- delegation depth and policy expiry.

It does not execute tools.

### `enforcement_broker.py`
Stateful AAB broker demonstrating:
- authenticated HMAC reference leases;
- lease version/key identity/not-before checks;
- optional external revocation hook;
- nonce replay protection and monotonic request sequence;
- request freshness;
- broker-owned cumulative budgets;
- exact model-envelope and policy-evaluation hashes;
- chained decision receipts;
- exact `execution_binding_hash` inside the receipt chain.

HMAC is used for reference portability only. Production keys must be protected outside the acting model.

### `capability_contract.py`
Validates adapter-specific security semantics that coarse operation/destination allowlists cannot express by themselves:
- allowed/required parameter keys;
- parameter value allowlists;
- effective destinations and credentials;
- redirect chains;
- filesystem effects;
- subprocess effects;
- secondary network destinations.

### `mediated_executor.py`
Binds the actual prepared effect to authorization:

```text
model request
  -> trusted adapter prepare
  -> immutable PreparedAction
  -> capability contract
  -> SHA-256 action binding
  -> broker decision containing same binding
  -> only ALLOW + matching binding
  -> same PreparedAction dispatched
```

The trusted adapter remains part of the enforcement plane and must accurately report the effective action.

### `durable_broker.py`
Adds durable authoritative security state:
- authenticated state envelope;
- SQLite `BEGIN IMMEDIATE` transaction serialization for cooperating local broker processes;
- reload-before-evaluate behavior;
- persisted replay/cumulative budget/receipt state;
- state generation, previous-state hash, and ancestry;
- independently retained checkpoint comparison;
- fail-closed persistence semantics.

This local reference design is not a distributed consensus or production key-management system.

### `delegation.py`
Verifies monotonic child policy derivation. A child cannot widen:
- objectives;
- operations;
- targets;
- destinations;
- credentials;
- capability-contract IDs;
- side-effect ceiling;
- budgets;
- expiry;
- delegation depth.

### `mediation_graph.py`
Checks a declared architecture for broker bypass by removing broker nodes and testing agent→side-effect reachability. It returns deterministic shortest witness paths.

This proves only the declared graph. Real A4 evaluation must enumerate actual equivalent-effect channels.

### `receipt_chain.py`
Creates/verifies SHA-256 chained decision receipts with explicit sequence and previous-receipt hash.

### `amcs.py`
AMCS reference runtime **0.3.0**, implementing the claimed AMCS v1.2.1 INTERNAL-profile surfaces with additional hardening:
- full chat crawl and explicit prompt/response omission accounting;
- required matrices/case files/case-study graph surfaces;
- cell index, copied schemas, verification log, manifests and seal receipt;
- cryptographic cell-root binding and optional HMAC root authentication;
- delta lineage fields;
- path-safe evidence collection;
- bounded traversal-safe archive extraction;
- immutable no-clobber cell/supercell creation;
- child-cell verification before supercell assembly.

## Run the suite

From the repository root:

```bash
python -m py_compile reference/*.py
python -m unittest discover -s tests -v
```

Policy-gate demo:

```bash
python reference/authority_gate.py \
  --policy examples/authority_policy.json \
  --requests examples/action_requests.json
```

AMCS round trip:

```bash
python reference/amcs.py seal \
  --input examples/chat_minimal.json \
  --out-dir out \
  --cell-name DEMO_CELL

python reference/amcs.py verify --cell out/DEMO_CELL.tar.gz
```

Authenticated reference root:

```bash
key=1111111111111111111111111111111111111111111111111111111111111111
python reference/amcs.py seal \
  --input examples/chat_minimal.json \
  --out-dir out \
  --cell-name AUTH_CELL \
  --seal-key-hex "$key"
python reference/amcs.py verify \
  --cell out/AUTH_CELL.tar.gz \
  --seal-key-hex "$key"
```

## Evidence boundary

A passing test suite establishes only the properties exercised by those tests under their assumptions. It does not establish:
- complete real-world mediation;
- trusted-adapter correctness for arbitrary tools;
- protection against compromise of the enforcement host or key services;
- certified deployment conformance;
- A4/frontier-model containment.

See `SECURITY.md`, `CONFORMANCE_PROFILES.md`, and `docs/THREAT_MODEL.md` before making security claims.
