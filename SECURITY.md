# Security Policy

AMAS, AAB, and AMCS are security-oriented research specifications and reference implementations. Security claims in this repository are intentionally scoped to documented mechanisms and tested assumptions.

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
- deterministic conflict arbitration and authority transitions;
- AAB leases, validity/revocation, replay state, cumulative budgets, and receipts;
- capability contracts and effective-action preparation;
- authorization-to-execution binding;
- monotonic delegation;
- transactional durable broker state and rollback/ancestry checkpoints;
- mediation/topology declarations;
- AMCS evidence collection, archive extraction, manifests, cell roots, sealing, and verification;
- credentials, signing/revocation/checkpoint keys, trusted adapters, and external anchor services.

## Current assurance boundary

The repository contains executable reference mechanisms, adversarial vectors, generated-artifact conformance tests, and CI.

It does **not** claim:

- certified production security;
- complete enumeration of a real deployment's equivalent-effect paths;
- resistance to compromise of the enforcement host, trusted adapter, OS, hypervisor, hardware, signing/revocation/checkpoint service, or other infrastructure outside the modeled boundary;
- frontier-model containment merely because unit/adversarial tests pass.

A production deployment must independently establish complete mediation, least privilege, secret isolation, accurate effective-effect modeling, transactional security state, protected key/anchor services, infrastructure isolation, and architecture-specific adversarial evaluation.

## Reference cryptography

HMAC-SHA256 is used in several reference examples because it is compact and available in the Python standard library. Symmetric secrets must not be exposed to the acting model in a production design.

AMCS cell roots support an unauthenticated cryptographic binding mode and an optional HMAC-authenticated mode. Hash consistency is not provenance authenticity; a protected signing/anchoring authority is required when authenticity matters.

## AMCS 0.3.0 filesystem/archive assumptions

AMCS treats archive contents, attachment metadata, identifiers, and existing output paths as potentially hostile or conflicting inputs.

The reference runtime:

- rejects path traversal, duplicate archive members, links, devices, FIFOs, and unsupported archive member types;
- applies member-count and expanded-size limits;
- constrains attachment paths to an explicit root;
- refuses to overwrite existing sealed cells/supercells;
- blocks sealing on unanswered prompts unless explicitly marked `no_response_required`;
- validates required generated surfaces;
- binds the content manifest, seal receipt, and cell index through `cell_root.json`;
- verifies child cells before supercell assembly.

These controls are not a substitute for OS-level sandboxing when processing untrusted data.

## AAB 0.4.1 enforcement assumptions

The reference broker assumes:

- lease/signing/revocation/checkpoint authority is outside model control;
- trusted adapters accurately report effective actions and security effects;
- configured capability contracts enumerate the relevant effect dimensions;
- the model cannot directly reach the underlying tool/credential through an alternate path;
- the local transactional store remains available/correct.

A deployment that violates those assumptions cannot inherit the corresponding reference assurance.

## Evidence categories

Security documentation and release notes should distinguish:

1. **specified property** — normative requirement;
2. **implemented mechanism** — present in reference code;
3. **tested property** — reproduced by automated/adversarial tests;
4. **deployment evidence** — demonstrated in a specific environment;
5. **independent certification/evaluation** — assessed under a defined external process.

A higher category must not be implied by evidence from a lower category.

## Supported status

The active draft surfaces are the versions identified on the current branch/release being evaluated. Historical snapshots, embedded bundles, and stale archives should not be assumed to contain later security fixes.
