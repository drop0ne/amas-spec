#!/usr/bin/env python3
"""Finite-epoch durable broker reference.

The base durable broker intentionally preserves complete nonce/receipt/ancestry
history. This subclass places an explicit event ceiling on an epoch so hostile or
very long-lived workloads cannot make the authenticated state grow without
bound. Reaching the ceiling fails closed; rotation requires an operator-retained
checkpoint rather than silently discarding replay evidence.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from durable_broker import DurableEnforcementBroker, DurabilityError
from enforcement_broker import EnforcementBroker


class BoundedDurableEnforcementBroker(DurableEnforcementBroker):
    def __init__(self, *args: Any, max_epoch_events: int = 10000, **kwargs: Any):
        if not isinstance(max_epoch_events, int) or isinstance(max_epoch_events, bool) or max_epoch_events < 1:
            raise ValueError("max_epoch_events must be a positive integer")
        self.max_epoch_events = max_epoch_events
        super().__init__(*args, **kwargs)
        if len(self.receipts) > self.max_epoch_events:
            raise DurabilityError("persisted broker epoch exceeds configured event ceiling")

    def capacity(self) -> dict[str, int | bool]:
        used = len(self.receipts)
        return {
            "max_epoch_events": self.max_epoch_events,
            "used_events": used,
            "remaining_events": max(self.max_epoch_events - used, 0),
            "rotation_required": used >= self.max_epoch_events,
        }

    def authorize(
        self,
        request: dict[str, Any],
        *,
        cost: dict[str, int],
        now: datetime | None = None,
        execution_binding_hash: str | None = None,
    ) -> dict[str, Any]:
        if self._poisoned:
            raise DurabilityError("broker instance is poisoned after persistence failure")
        with self._exclusive_state_transaction():
            if self.state_path.exists():
                self._restore(checkpoint=self._checkpoint, checkpoint_key=self._checkpoint_key)
            if len(self.receipts) >= self.max_epoch_events:
                raise DurabilityError("broker epoch capacity exhausted; checkpoint and rotate state")
            receipt = EnforcementBroker.authorize(
                self,
                request,
                cost=cost,
                now=now,
                execution_binding_hash=execution_binding_hash,
            )
            try:
                self._persist()
            except Exception:
                self._poisoned = True
                raise
            return receipt
