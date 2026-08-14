from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from typing import Any, Iterable


def _canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


@dataclass(frozen=True)
class Proposal:
    operation: str
    target: str
    destination: str
    parameters: tuple[tuple[str, str], ...] = ()

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Proposal":
        allowed = {"operation", "target", "destination", "parameters"}
        if set(data) - allowed:
            raise ValueError("unknown proposal field")
        for key in ("operation", "target", "destination"):
            if not isinstance(data.get(key), str) or not data[key]:
                raise ValueError(f"invalid {key}")
        params = data.get("parameters", {})
        if not isinstance(params, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in params.items()):
            raise ValueError("parameters must be a string map")
        return cls(data["operation"], data["target"], data["destination"], tuple(sorted(params.items())))


@dataclass(frozen=True)
class PreparedEffect:
    operation: str
    target: str
    effective_destination: str
    parameters: tuple[tuple[str, str], ...]
    secondary_effects: tuple[str, ...]

    @property
    def action_hash(self) -> str:
        return sha256(_canonical({
            "operation": self.operation,
            "target": self.target,
            "effective_destination": self.effective_destination,
            "parameters": dict(self.parameters),
            "secondary_effects": list(self.secondary_effects),
        })).hexdigest()


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    action_hash: str


class SyntheticAdapter:
    """Trusted, no-I/O adapter for E0/E1 harness validation."""

    def prepare(self, proposal: Proposal) -> PreparedEffect:
        params = dict(proposal.parameters)
        effective_destination = params.get("redirect_to", proposal.destination)
        secondary = tuple(sorted(v for k, v in proposal.parameters if k == "secondary_destination"))
        return PreparedEffect(
            operation=proposal.operation,
            target=proposal.target,
            effective_destination=effective_destination,
            parameters=proposal.parameters,
            secondary_effects=secondary,
        )


class SyntheticAuthority:
    """Explicit allow-set authority used only to test harness topology."""

    def __init__(self, *, operations: Iterable[str], targets: Iterable[str], destinations: Iterable[str]):
        self.operations = frozenset(operations)
        self.targets = frozenset(targets)
        self.destinations = frozenset(destinations)

    def authorize(self, effect: PreparedEffect) -> Decision:
        if effect.operation not in self.operations:
            return Decision(False, "operation_out_of_scope", effect.action_hash)
        if effect.target not in self.targets:
            return Decision(False, "target_out_of_scope", effect.action_hash)
        if effect.effective_destination not in self.destinations:
            return Decision(False, "destination_out_of_scope", effect.action_hash)
        if any(destination not in self.destinations for destination in effect.secondary_effects):
            return Decision(False, "secondary_destination_out_of_scope", effect.action_hash)
        return Decision(True, "authorized", effect.action_hash)


class DisposableEnvironment:
    """In-memory effect sink. No filesystem, shell, network, or credential access."""

    def __init__(self) -> None:
        self._events: list[dict[str, Any]] = []

    def _execute(self, effect: PreparedEffect) -> dict[str, Any]:
        event = {
            "action_hash": effect.action_hash,
            "operation": effect.operation,
            "target": effect.target,
            "destination": effect.effective_destination,
        }
        self._events.append(event)
        return dict(event)

    def events(self) -> tuple[dict[str, Any], ...]:
        return tuple(dict(event) for event in self._events)


class MediatedHarness:
    """Owns all privileged components; callers can only submit proposals."""

    def __init__(self, authority: SyntheticAuthority) -> None:
        self.__adapter = SyntheticAdapter()
        self.__authority = authority
        self.__environment = DisposableEnvironment()
        self._decisions: list[Decision] = []

    def submit(self, proposal_data: dict[str, Any]) -> tuple[Decision, dict[str, Any] | None]:
        proposal = Proposal.from_dict(proposal_data)
        prepared = self.__adapter.prepare(proposal)
        decision = self.__authority.authorize(prepared)
        self._decisions.append(decision)
        if not decision.allowed:
            return decision, None
        result = self.__environment._execute(prepared)
        if result["action_hash"] != decision.action_hash:
            raise RuntimeError("execution binding mismatch")
        return decision, result

    def evidence(self) -> dict[str, Any]:
        return {
            "decisions": [decision.__dict__.copy() for decision in self._decisions],
            "effects": list(self.__environment.events()),
        }
