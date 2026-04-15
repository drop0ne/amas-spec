# AMAS Threat Model

## Scope

This document identifies the threats that AMAS is designed to mitigate, the threats it partially addresses, and the threats that fall outside its scope.

---

## Threats AMAS Mitigates

### T1: Tier Impersonation (Prompt Injection)

**Description.** A low-tier source (Tier 2 or 3) includes language that impersonates a higher-tier source.

**AMAS mitigation.** Authority tier is assigned at ingestion based on source identity, not content. Rule 1 rejects any attempt by a lower tier to override a higher tier.

**Residual risk.** If the ingestion layer misclassifies a source's tier, the entire model is compromised.

### T2: Implicit Authority Escalation

**Description.** An inference (Tier 3) is treated as established fact (Tier 2 or higher) without explicit escalation.

**AMAS mitigation.** All Tier 3 content must carry `inference_marker: true`. Escalation requires explicit action by an authorized agent.

**Residual risk.** If middleware fails to tag model-generated content, the inference boundary becomes invisible.

### T3: Provenance Opacity

**Description.** A decision is made through the model but no one can trace which sources contributed to it or at what authority level.

**AMAS mitigation.** Every Memory Object carries provenance metadata. Conflict resolution events may produce audit records. The AMCS reference implementation enforces provenance on every derived artifact.

**Residual risk.** Implementations that cut corners on provenance reduce auditability without obvious immediate failure.

### T4: Canonical Root Ambiguity

**Description.** Multiple artifacts are treated as if each were the canonical root for the same active context.

**AMAS mitigation.** Core doctrine requires exactly one canonical root, proven unique before hydrate completes.

**Residual risk.** If runtime binding does not actually verify uniqueness, the doctrine can be bypassed in practice.

### T5: Writable Truth-Source Drift

**Description.** Multiple writable surfaces exist and operators cannot tell which ledger is authoritative.

**AMAS mitigation.** Core doctrine requires exactly one writable truth ledger.

**Residual risk.** If derived artifacts are allowed to behave like writable peers, the drift reappears operationally.

### T6: Silent Repair

**Description.** Runtime infrastructure silently rewrites state, wrappers, or chain tips without an explicit repair receipt.

**AMAS mitigation.** Silent repair is forbidden. All repairs require receipts.

**Residual risk.** Authorized bad-faith actors or compromised runtimes can still falsify repairs unless the operator-visible verification seam is actually inspected.

### T7: Derived Artifacts Gating Reads

**Description.** A manifest, wrapper, or index becomes the practical gatekeeper of access to canon, even though it is only a derived view.

**AMAS mitigation.** Derived artifacts may summarize truth but may not define truth or gate reads.

**Residual risk.** Convenience layers can reintroduce read-gating by implementation if left unaudited.

### T8: Replay Risk on Activation or Export Receipts

**Description.** A valid but stale activation/export artifact is replayed against newer runtime state.

**AMAS mitigation.** Runtime binding requires timestamped receipts and operator-visible state hashes.

**Residual risk.** Replay remains possible if freshness checks are not enforced by the runtime.

---

## Threats AMAS Partially Addresses

### T9: Multi-Agent Authority Dilution

**Description.** In multi-agent systems, authority degrades as outputs pass from agent to agent.

**AMAS partial mitigation.** If both agents implement AMAS, metadata can propagate.

**Gap.** AMAS does not yet define a full inter-agent authority negotiation protocol.

### T10: Stale Authority

**Description.** A Memory Object was valid when created but circumstances changed.

**AMAS partial mitigation.** `expires_at` and explicit supersession support time-bounded authority.

**Gap.** AMAS does not automatically detect staleness.

---

## Threats Outside AMAS Scope

### T11: Compromised Tier 0 Channel

If the infrastructure delivering Tier 0 is compromised, AMAS provides no defense.

### T12: Authorized Malicious Agents

An agent with legitimate Tier 1 authority who intentionally creates harmful instructions remains within the formal AMAS structure.

### T13: Memory Object Boundary Errors

If the system incorrectly defines object boundaries, conflict resolution may still produce incorrect results.

### T14: Side-Channel Attacks

AMAS does not address attacks that bypass the context window entirely — model weight manipulation, training-data poisoning, or hardware-level exploits.
