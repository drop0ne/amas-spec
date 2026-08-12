# AMCS Runtime — Reference Implementation

**AMCS Version:** 0.1.1 reference runtime  
**Implements:** AMCS v1.2.1 INTERNAL profile  
**Language:** Python 3.11+  
**Dependencies:** Standard library only

## AMCS

`amcs.py` is the persistence/sealing reference implementation operating under AMAS governance. It converts chat conversations into immutable, hash-verified memory-cell bundles with provenance tracking.

```bash
python3 reference/amcs.py seal --input examples/chat_minimal.json --out-dir out --cell-name MY_CELL
python3 reference/amcs.py verify --cell out/MY_CELL.tar.gz
```

AMCS demonstrates memory provenance, explicit rehydration, integrity verification, epistemic strata, and sealed-memory behavior. It does not claim to be an external action sandbox.

## AAB Authority Gate

`authority_gate.py` is a separate reference component for the AMAS **Agent Authority Boundary (AAB)**. It evaluates proposed side effects against an explicit, expiring authority lease and never executes the action itself.

```bash
python3 reference/authority_gate.py \
  --policy examples/authority_policy.json \
  --requests examples/action_requests.json
```

Expected demonstration behavior includes:

- in-scope observation → `ALLOW`
- unlisted target → `ESCALATE` when operator escalation is enabled
- unlisted credential / excessive side effect → `DENY`

Run tests:

```bash
python3 -m unittest discover -s tests -v
```

## Separation of responsibilities

- **AMAS Core** — authority doctrine.
- **Runtime Binding** — memory/runtime lifecycle mechanics.
- **AMCS** — sealing, integrity, provenance, persistence reference runtime.
- **AAB** — external action authorization boundary.

Production AAB deployments require an execution gateway the model cannot bypass, plus conventional sandboxing, least privilege, egress controls, secret isolation, rate limits, and tamper-evident logging.
