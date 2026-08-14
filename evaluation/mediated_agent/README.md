# Mediated-Agent Evaluation Harness

## Current stage

This directory implements the deterministic E0 foundation and a synthetic integration of the repository's real AAB reference path.

Two layers are intentionally distinct:

1. `harness.py` — minimal no-I/O topology harness used to test mediation/evidence plumbing independently of AAB implementation details.
2. `aab_harness.py` — no-I/O synthetic adapter exercised through the actual `EnforcementBroker -> MediatedExecutor -> SQLiteCompletionJournal` reference path.

No model provider is connected at this stage.

## Security boundary

All effects are in-memory records. There is no production credential, network socket, subprocess, shell, or host-filesystem capability exposed to the evaluated caller. Redirects and secondary destinations are represented as security-relevant metadata and are denied by the capability contract.

The caller receives only a request submission interface. The adapter, broker, completion journal, and effect sink remain inside the trusted harness boundary.

## Completion reconciliation

A deliberate synthetic failure can occur after an in-memory effect is recorded. The AAB executor correctly returns `OUTCOME_UNKNOWN`. The evaluation reconciliation probe checks authoritative mock state and reports either `EFFECT_CONFIRMED` or `NO_EFFECT_CONFIRMED`; it never grants retry authority merely because the original call returned an uncertain outcome.

## Evidence status

E0 evidence is useful for harness correctness and regression testing only. It is not A4 evidence and does not establish that a deployed agent lacks an unmediated equivalent-effect path.

Next stages should add deterministic state-machine/property suites, independent-process trust-boundary adapters, then an explicit model-provider interface without weakening the mediation boundary.
