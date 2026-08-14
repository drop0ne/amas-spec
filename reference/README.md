# Reference Implementations

The code in this directory is executable **reference material**, not a production security appliance. Each module demonstrates a bounded property of AMAS, AAB, or AMCS and is intentionally reviewable.

## Current reference surfaces

### `memory_object_validation.py`
Strict standard-library admission checks for AMAS Memory Objects before authority arbitration. Escalation and supersession remain distinct authority-bearing transitions.

### `conflict_resolution.py`
Implements semantic-role admissibility, full Memory Object admission, tier precedence, externally authorized/traceable supersession, structural `scope_path` specificity, recency, and fail-closed `HALT_ESCALATE` fallback.

### `authority_gate.py`
Stateless deny-by-default AAB policy evaluation. Its public validators are shared by the broker and delegation implementation so root/child authority objects do not acquire different meanings in different components. It does not execute tools.

### `enforcement_broker.py`
Stateful broker with exact signed-lease envelope admission, authenticated HMAC reference leases, not-before/expiry/revocation checks, replay/sequence controls, request freshness, broker-owned budgets, chained decision receipts, and exact execution-binding hashes.

HMAC is a compact reference mechanism only. Production keys must live outside the acting model/runtime failure domain.

### `capability_contract.py`
Content-addressed adapter-specific constraints for parameters, effective destinations/credentials, redirects, filesystem effects, subprocesses, and secondary destinations.

### `mediated_executor.py`
Binds the exact immutable prepared action to authorization and records completion state:

```text
model request
  -> trusted adapter prepare
  -> immutable PreparedAction
  -> capability contract
  -> broker receipt containing exact action hash
  -> completion journal STARTED
  -> same PreparedAction dispatched
  -> SUCCEEDED or OUTCOME_UNKNOWN
```

A filesystem-backed SQLite completion journal is the durable reference mode. An exception after dispatch is `OUTCOME_UNKNOWN`, not proof that no effect occurred. See `docs/COMPLETION_INTEGRITY.md`.

### `durable_broker.py`
Authenticated durable state, SQLite transaction serialization, reload-before-evaluate behavior, replay/budget/receipt persistence, state ancestry, checkpoint comparison, and fail-closed persistence.

### `bounded_durable_broker.py`
Finite durable-state epochs. Reaching the configured event ceiling fails closed and requires explicit checkpoint/rotation rather than silent loss of replay/receipt/ancestry evidence.

These local references are not distributed consensus or production key-management systems.

### `delegation.py`
Monotonic child-policy derivation using the same policy admission rules as the gate/broker. Exact parent identity/hash are bound and child scope cannot widen.

### `mediation_graph.py`
Checks a declared architecture for broker bypass by graph reachability. This proves only the declared graph; A4 requires empirical enumeration of real equivalent-effect channels.

### `receipt_chain.py`
SHA-256 chained decision receipts with explicit sequence and previous-receipt hash.

### `amcs.py`
Low-level AMCS archive/sealing engine **0.3.3** providing the tested persistence, provenance, no-clobber, archive-safety, cell-root, delta, and supercell mechanics.

### `amcs_schema_validation.py`
Validates supported JSON input and normative generated AMCS JSON surfaces against the repository Draft 2020-12 schemas.

### `amcs_runtime.py`
**Supported AMCS conformance entrypoint.** It combines the AMCS engine with strict JSON-message admission and generated-artifact schema validation. Use this entrypoint for seal/verify evidence claims.

The current reference does not parse ODT semantics into structured canonical narrative and does not automate semantic contradiction/authority reconciliation across supercell children. Those richer semantics are not claimed as implemented merely because archive assembly exists.

## C/C++ portability

`include/amas/types.h` defines the fixed-width C-compatible type profile. CI compiles it as C11 and C++17. Canonical JSON wire integer limits remain narrower than native 64-bit ranges where required for exact JSON interoperability.

## Run the suite

```bash
python -m pip install -r requirements.txt
python -m py_compile reference/*.py
cc -std=c11 -Wall -Wextra -Werror -pedantic -Iinclude -fsyntax-only tests/c_portability_smoke.c
c++ -std=c++17 -Wall -Wextra -Werror -pedantic -Iinclude -fsyntax-only tests/cpp_portability_smoke.cpp
python -m unittest discover -s tests -v
```

Policy-gate demo:

```bash
python reference/authority_gate.py \
  --policy examples/authority_policy.json \
  --requests examples/action_requests.json
```

Schema-validating AMCS round trip:

```bash
python reference/amcs_runtime.py seal \
  --input examples/chat_minimal.json \
  --out-dir out \
  --cell-name DEMO_CELL
python reference/amcs_runtime.py verify --cell out/DEMO_CELL.tar.gz
```

## Evidence boundary

A passing test suite establishes only the properties exercised by those tests under their assumptions. It does not establish complete real-world mediation, trusted-adapter correctness for arbitrary tools, distributed exactly-once effects, protection after enforcement/key-service compromise, certified deployment conformance, or A4/frontier-model containment.

See `SECURITY.md`, `CONFORMANCE_PROFILES.md`, `docs/THREAT_MODEL.md`, and the root `README.md` before making security claims.
