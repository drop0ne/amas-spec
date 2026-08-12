# Security Policy

AMAS, AAB, and AMCS are security-oriented reference specifications and implementations. Security claims in this repository are intentionally scoped to documented mechanisms and tested assumptions.

## Reporting a vulnerability

Do not publish a reproducible vulnerability, exploit path, secret, or sensitive deployment detail in a public issue.

For this repository, prefer GitHub's private security-advisory/reporting channel when available. If that channel is unavailable, contact the repository owner privately through an established GitHub communication channel before publishing technical details.

A useful report should include:

- affected commit or release;
- affected component and configuration;
- preconditions and trust assumptions;
- minimal reproduction steps;
- observed impact;
- expected fail-closed behavior;
- whether the issue crosses a documented AMAS/AAB/AMCS authority boundary.

Please avoid destructive testing against systems you do not own or lack explicit permission to evaluate.

## Security-sensitive components

The following surfaces should be treated as security boundaries rather than ordinary utility code:

- AMAS authority-tier classification and conflict arbitration;
- AAB authority leases, replay state, cumulative budgets, and decision receipts;
- monotonic parent→child delegation;
- durable broker state and rollback checkpoints;
- mediation/topology declarations;
- AMCS archive extraction, evidence collection, manifests, sealing, and verification;
- credentials, signing keys, checkpoint keys, and external tool adapters.

## Current assurance boundary

The repository contains executable reference mechanisms and conformance tests. It does **not** claim:

- certified production security;
- complete enumeration of a real deployment's equivalent-effect paths;
- resistance to compromise of the enforcement host, signing service, operating system, hypervisor, hardware, or other infrastructure outside the modeled boundary;
- frontier-model containment merely because reference tests pass.

A production deployment must independently establish complete mediation of side effects, least-privilege identity and secret handling, isolation, transactional enforcement state, durable external evidence, and architecture-specific adversarial evaluation.

## Reference cryptography

Some AAB examples use HMAC-SHA256 because it is available in the Python standard library and keeps the reference implementation small. Symmetric signing material must not be exposed to the acting model in a production design. Deployments should use identity, signing, and key-management mechanisms appropriate to their trust architecture.

## AMCS archive and filesystem assumptions

AMCS 0.2.0 treats archive contents, message attachment metadata, and cell/supercell identifiers as potentially hostile inputs.

The reference runtime therefore rejects archive traversal, links/special files, unsafe identifiers, attachment-root escape, oversized archive expansion, and failed pre-seal verification. These controls reduce specific filesystem/archive risks; they are not a substitute for OS-level sandboxing when processing untrusted data.

## Evidence and disclosure discipline

Security documentation should distinguish:

1. **specified property** — required by normative documentation;
2. **implemented mechanism** — present in reference code;
3. **tested property** — reproduced by automated or adversarial tests;
4. **deployment evidence** — demonstrated in a particular environment;
5. **certified claim** — independently assessed under a defined certification process.

A higher category must not be implied by evidence from a lower category.

## Supported status

The active draft surfaces are the versions identified on the repository's current default branch. Historical snapshots and embedded/exported bundles should not be assumed to contain later security fixes.
