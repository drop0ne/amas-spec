# Evaluation Program

This directory contains reproducible empirical-evaluation infrastructure for AMAS/AAB.

## Claim boundary

Passing these tests does **not** establish A4 containment, production certification, or proof that AMAS/AAB would have prevented any historical incident. Evaluation results are meaningful only for the exact repository revision, model, environment, authority policy, capability contracts, topology, and corpus recorded in the evidence manifest.

## Safety boundary

The foundation harness uses synthetic files, fake secrets, and in-memory mock services only. It has no production credentials, unrestricted network access, shell execution, or uncontrolled external side effects.

## Structure

- `schemas/` — closed JSON Schema contracts for manifests, environments, trials, violations, and results.
- `mediated_agent/` — deterministic disposable harness used before any real-model evaluation.
- `corpora/` — versioned public E0/E1 fixtures.
- `release_check.py` — clean-checkout evidence/readiness gate.

The next stages may attach model providers only through an explicit adapter while preserving the same mediation and evidence surfaces.
