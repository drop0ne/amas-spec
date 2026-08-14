# AAB Execution Binding

**Status:** AAB 0.4.1 reference documentation index

This page is intentionally concise so execution-boundary rules have one maintained source instead of multiple drifting copies.

Use these canonical references:

- `docs/AGENT_AUTHORITY_BOUNDARY.md` — authority, effective-action binding, durable state, mediation, and evidence rules;
- `docs/COMPLETION_INTEGRITY.md` — authorization-versus-completion semantics;
- `reference/mediated_executor.py` — executable prepared-action and completion-state reference;
- `reference/enforcement_broker.py` — chained decision record containing the exact prepared-action binding;
- `schemas/effect_completion.schema.json` — portable completion-record shape.

A conforming reference path preserves these properties:

1. The trusted adapter resolves the effective action before authorization.
2. Applicable capability-contract constraints are evaluated before authorization.
3. The prepared action is immutable and receives a Canonical JSON v1 SHA-256 binding.
4. That exact binding is included in the broker decision record.
5. A real dispatch occurs only after matching authorization and durable authorization-state persistence.
6. Completion state is recorded as `STARTED` before dispatch.
7. Adapter return becomes `SUCCEEDED`; uncertain post-dispatch outcome becomes `OUTCOME_UNKNOWN`.
8. `OUTCOME_UNKNOWN` is not proof that nothing occurred and is not an automatic retry signal.
9. Deployment evidence must still establish that equivalent effects cannot bypass the mediation boundary.

Authorization, dispatch, and completion are separate auditable facts.
