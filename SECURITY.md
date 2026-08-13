# Security Policy

AMAS, AAB, and AMCS are security-oriented research specifications and reference implementations. Security claims in this repository are intentionally scoped to documented mechanisms, executable reference behavior, and tested assumptions.

## Reporting a vulnerability

Do not publish a reproducible exploit path, secret, or sensitive deployment detail in a public issue.

Prefer GitHub's private security-advisory/reporting channel when available. Otherwise contact the repository owner privately through an established channel before publishing technical details.

A useful report should identify:

- affected commit/release;
- component/configuration;
- preconditions and trust assumptions;
- minimal reproduction;
- observed impact;
- expected fail-closed behavior;
- whether the issue crosses an AMAS/AAB/AMCS authority boundary.

Do not perform destructive testing against systems you do not own or lack explicit authorization to evaluate.

## Security-sensitive components

Treat these as security boundaries rather than ordinary utility code:

- AMAS authority-tier and semantic-role classification;
- Memory Object admission, provenance, authority transitions, and deterministic conflict arbitration;
- trusted supersession authorization;
- AAB leases, validity/revocation, replay state, cumulative budgets, and receipts;
- capability contracts and effective-action preparation;
- authorization-to-execution binding and completion-state persistence;
- monotonic delegation;
- transactional durable broker state, bounded epochs, rollback/ancestry checkpoints;
- mediation/topology declarations;
- AMCS input admission, evidence collection, archive extraction, manifests, cell roots, sealing, schema validation, and verification;
- credentials, signing/revocation/checkpoint keys, trusted adapters, and external anchor/persistence services.

## Current assurance boundary

The repository contains executable reference mechanisms, adversarial vectors, generated-artifact/schema conformance tests, C/C++ portability checks, and CI.

It does **not** claim:

- certified production security;
- complete enumeration of a real deployment's equivalent-effect paths;
- distributed exactly-once semantics for external effects;
- resistance to compromise of the enforcement host, trusted adapter, OS, hypervisor, hardware, signing/revocation/checkpoint/completion service, or other infrastructure outside the modeled boundary;
- frontier-model containment merely because unit/adversarial tests pass.

A production deployment must independently establish complete mediation, least privilege, secret isolation, accurate effective-effect modeling, transactional security state, protected key/anchor/completion services, infrastructure isolation, service-specific idempotency/reconciliation, and architecture-specific adversarial evaluation.

## Reference cryptography

HMAC-SHA256 is used in several reference examples because it is compact and widely available. Symmetric secrets must not be exposed to the acting model in a production design.

AMCS cell roots support an unauthenticated cryptographic binding mode and an optional HMAC-authenticated mode. Hash consistency is not provenance authenticity; a protected signing/anchoring authority is required when authenticity matters.

## AMCS 0.3.3 filesystem/archive assumptions

AMCS treats archive contents, attachment metadata, identifiers, existing output paths, and supported JSON message input as potentially hostile or conflicting inputs.

`reference/amcs.py` is the low-level archive/sealing engine. `reference/amcs_runtime.py` is the supported conformance entrypoint and adds strict JSON-message admission plus Draft 2020-12 validation of the generated JSON surfaces claimed by the reference runtime.

The reference path:

- rejects path traversal, duplicate archive members, links, devices, FIFOs, and unsupported archive member types;
- applies member-count and expanded-size limits;
- constrains attachment paths to an explicit root;
- refuses to overwrite existing sealed cells/supercells;
- blocks sealing on unanswered prompts unless explicitly marked `no_response_required`;
- rejects schema-incompatible supported JSON input before sealing;
- validates claimed generated JSON surfaces against repository schemas;
- binds the content manifest, seal receipt, and cell index through `cell_root.json`;
- verifies child cells before supercell assembly.

The current reference may bind/copy an ODT but does not parse ODT document semantics into structured canonical narrative. The supercell helper bundles verified children but does not automate cross-cell semantic contradiction/authority reconciliation. Those semantics must not be implied from archive assembly alone.

These controls are not a substitute for OS-level sandboxing when processing untrusted data.

## AAB 0.4.1 enforcement assumptions

The reference broker/executor assumes:

- lease/signing/revocation/checkpoint authority is outside model control;
- signed lease envelopes and embedded policies satisfy the exact closed runtime/schema contracts;
- trusted adapters accurately report effective actions and security effects;
- configured capability contracts enumerate relevant effect dimensions;
- the model cannot directly reach the underlying tool/credential through an alternate path;
- authorization and completion-state stores remain available/correct and outside model control;
- any external system that needs retry safety provides suitable reconciliation, idempotency, or transactional support.

A deployment that violates those assumptions cannot inherit the corresponding reference assurance.

### Supersession

A Memory Object's `supersedes` field is not self-authenticating. The reference conflict resolver requires traceable provenance **and** a trusted external supersession authorizer confirming authority over the superseded tier/scope. Missing, false, malformed, or failing authorization checks halt/escalate the conflict.

### Completion uncertainty

`ALLOW` proves authorization of the exact prepared action; it does not prove the external effect's outcome.

The mediated reference records `STARTED` before adapter dispatch. Adapter return is `SUCCEEDED`; uncertainty after dispatch is `OUTCOME_UNKNOWN`. A lingering `STARTED` after recovery is also interpreted as `OUTCOME_UNKNOWN`. That state must not be treated as permission for an automatic retry.

### Durable-state growth

The base durable broker preserves complete replay/receipt/ancestry history for clarity. `BoundedDurableEnforcementBroker` provides finite epochs for longer-lived use. Epoch exhaustion fails closed and requires explicit checkpoint/rotation rather than silently deleting replay evidence.

## Portable type assumptions

Normative security/wire values must map to fixed-width C/C++-compatible domains. `include/amas/types.h` and `docs/PORTABLE_TYPES.md` define the reference profile. Canonical JSON security integers remain limited to `±(2^53-1)` even though C/C++ storage may use `int64_t`/`uint64_t`, preserving exact cross-runtime JSON behavior.

## Evidence categories

Security documentation and release notes should distinguish:

1. **specified property** — normative requirement;
2. **implemented mechanism** — present in reference code;
3. **tested property** — reproduced by automated/adversarial tests;
4. **deployment evidence** — demonstrated in a specific environment;
5. **independent certification/evaluation** — assessed under a defined external process.

A higher category must not be implied by evidence from a lower category.

## Supported status

The active draft surfaces are the versions identified on the current branch/release being evaluated. Historical snapshots, embedded bundles, stale archives, and unmerged branches should not be assumed to contain later fixes.

The repository is currently **All Rights Reserved**. Security review does not imply an open-source license or permission to copy/reuse repository contents beyond applicable law or explicit written authorization.
