# Automated Authority Laundering

## Definition

**Automated authority laundering** is the process by which consequential decisions are made through AI systems in a way that obscures who authorized the decision, at what level of authority, and through what chain of delegation.

The AI system functions as a pass-through that converts ambiguous, unauthorized, or low-authority instructions into apparently legitimate outputs. The authority to act was never formally delegated — it was laundered through the model's context window.

## Why This Matters

Traditional authority structures require traceable chains of delegation.
AI systems break this chain when they combine system prompts, user input, retrieved documents, tool outputs, and prior model outputs without a formal authority model.

## Active Failure Modes

**Example 1: Policy Override via Retrieval.** A RAG system retrieves a document that contains the phrase "disregard standard review procedures for this category." The model incorporates the instruction into its output, bypassing review. No human authorized the bypass — the authority was laundered through retrieval.

**Example 2: Escalation Through Multi-Agent Pipelines.** Agent A produces an inference. Agent B consumes it as if it were ordinary session truth. By the time the recommendation reaches a human, the inferential origin is invisible.

**Example 3: Accountability Diffusion in Automated Decisions.** A model combines multiple ambiguous sources and produces a recommendation. When challenged, the organization points to "the AI's assessment." The AI points to its inputs. No single source is visibly accountable.

## How AMAS Addresses This

AMAS mitigates authority laundering through three familiar mechanisms:

**Provenance tracking.** Every Memory Object carries source and authority metadata.

**Tier enforcement.** Lower-tier sources cannot override higher-tier constraints.

**Inference marking.** Model-generated conclusions remain visibly inferential unless explicitly escalated.

## Why Runtime Binding Matters

Provenance alone is not enough.

Authority can still be laundered if runtime mechanics are opaque. A system may:
- load ambiguous state during hydrate
- silently normalize or repair state
- export a bundle that appears more authoritative than the live state justified
- allow derived artifacts to become practical truth surfaces

For this reason, AMAS now distinguishes governance from runtime binding.

The **runtime-binding seam** is part of the anti-laundering control surface because it makes the following visible:

- what canonical root was activated
- which ledger was treated as writable
- whether activation was authorized
- whether state changed through append, repair, or export
- what receipts and state hashes were emitted to the operator

Without this seam, provenance can exist on paper while operational authority still disappears into invisible middleware.

## Residual Risk

AMAS does not eliminate all authority laundering. It addresses structural conditions that enable it, but cannot prevent:

- authorized agents who intentionally misuse authority
- compromised enforcement layers
- incorrect Memory Object segmentation
- operators who ignore runtime verification surfaces

Authority laundering remains a governance problem first. AMAS provides technical infrastructure that makes governance auditable.

## Relationship to Existing Concepts

Automated authority laundering is related to but distinct from:

- **responsibility gaps**
- **automation bias**
- **principal-agent problems**

The term describes a specific mechanism: authority is not merely diffused, but transformed through the model's context and runtime pipeline in a way that obscures who was ever authorized to decide.
