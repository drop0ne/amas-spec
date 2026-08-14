# E2 Model-Provider Boundary

Status: **readiness contract only**. This document does not claim an E2 model evaluation has occurred.

## Purpose

E2 introduces a model provider only as an **untrusted planner**. The provider may propose an operation, target, destination, credential reference, side-effect class, and adapter parameters. Provider output is data. It is not authority.

A trusted proposal binder supplies all authority-bearing envelope identity before the proposal can reach the existing AAB execution path.

```text
trusted evaluation task
        |
        v
untrusted model provider
        |
        | proposal data only
        v
TrustedProposalBinder
        |
        | trusted lease/principal/objective/request/nonce/sequence/timestamp/contract identity
        v
EnforcementBroker
        v
MediatedExecutor
        v
capability contract
        v
completion journal
        v
synthetic adapter/effect sink
```

## Provider-authorized data

The provider contract permits only:

- `operation`
- `target`
- `destination`
- `credential_ref`
- `side_effect`
- `parameters`

The provider proposal schema is closed. Unknown fields fail before authority binding.

## Trusted binder fields

The provider cannot supply or override:

- adapter identity;
- lease identity;
- principal identity;
- objective identity;
- request identity;
- nonce;
- sequence;
- request timestamp;
- broker-owned usage/cost accounting;
- capability-contract identity;
- lease signing keys;
- broker state keys;
- checkpoint keys;
- completion-journal storage;
- trust-boundary identity secrets.

A malformed or unavailable provider does not consume a binder sequence number and does not create an adapter effect.

## Capability and effect mediation

A syntactically valid provider proposal is not automatically authorized. The trusted binder only creates the broker request envelope. The resulting request must still pass the same AAB policy, cumulative budgets, replay state, execution binding, capability contract, completion journal, and adapter mediation used by E1.

Provider attempts to redirect, reach an unapproved filesystem path, request a subprocess, use an unauthorized credential, or select an out-of-scope target/destination are expected to fail before any synthetic effect occurs.

## Real-provider requirements

A future provider implementation must keep provider API/network credentials in the evaluation control plane. They must not be placed in prompts, model-visible tool state, AAB action requests, capability-contract parameters, or synthetic/production adapter credentials.

A real-provider evaluation should record at minimum:

- provider ID;
- model ID;
- provider/model version when available;
- exact repository commit;
- task hash;
- proposal hash;
- policy, lease, capability-contract, corpus, schema, harness, and result hashes;
- model sampling/configuration metadata relevant to reproducibility;
- provider errors/timeouts as fail-closed outcomes;
- the trust-boundary mode actually used.

Raw provider secrets must not be persisted in evidence artifacts.

## Evidence boundary

The offline `ScriptedProvider` exists only to test the provider interface deterministically. Passing those tests is **E2 readiness evidence**, not E2 model-performance or containment evidence.

Connecting a real model provider is a separate evaluation increment. Even after such an evaluation, same-process or same-host trust services do not establish A4 independent containment. Production certification, independent-failure-domain containment, and claims that a historical incident would have been prevented remain out of scope unless separately evidenced.
