import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REFERENCE = ROOT / "reference"
sys.path.insert(0, str(REFERENCE))

from capability_contract import bind_contract_id
from enforcement_broker import EnforcementBroker, sign_lease
from mediated_executor import MediatedExecutor, PreparedAction

NOW = datetime(2026, 8, 12, 22, 30, tzinfo=timezone.utc)
KEY = b"mediated-executor-test-key"

CAPABILITY_CONTRACT = bind_contract_id({
    "adapter_id": "mock",
    "operation": "read",
    "allowed_parameter_keys": ["path", "mode"],
    "required_parameter_keys": ["path"],
    "unrestricted_parameter_keys": [],
    "parameter_allowlists": {"path": ["/record"], "mode": ["metadata"]},
    "allowed_effective_destinations": ["sandbox://allowed"],
    "allowed_credentials": ["read-token"],
    "allow_redirects": False,
    "allowed_filesystem_paths": [],
    "allow_subprocess": False,
    "allowed_subprocesses": [],
    "allowed_secondary_destinations": [],
})
CAP_ID = CAPABILITY_CONTRACT["contract_id"]


def capability_contract():
    return dict(CAPABILITY_CONTRACT)


def lease(max_network_calls=5, *, with_contract=False):
    value = {
        "lease_version": 1,
        "lease_id": "LEASE-X",
        "issuer": "operator",
        "key_id": "mediated-test-key",
        "issued_at": "2026-08-12T22:00:00Z",
        "not_before": "2026-08-12T22:00:00Z",
        "max_request_age_seconds": 3600,
        "signature_alg": "HMAC-SHA256",
        "policy": {
            "policy_id": "PX",
            "principal": "agent",
            "objectives": ["inspect"],
            "operations": ["read"],
            "targets": ["sandbox://allowed"],
            "destinations": ["sandbox://allowed"],
            "credentials": ["read-token"],
            "capability_contracts": [CAP_ID] if with_contract else [],
            "max_side_effect": "observe",
            "budgets": {
                "max_actions": 10,
                "max_network_calls": max_network_calls,
                "max_egress_bytes": 1000,
                "max_wall_clock_seconds": 60,
            },
            "max_delegation_depth": 0,
            "expires_at": "2026-08-13T00:00:00Z",
            "operator_escalation": False,
        },
    }
    value["signature"] = sign_lease(value, KEY)
    return value


def request(seq=1, nonce="nonce-00000000001", target="sandbox://allowed", side_effect="observe", *, with_contract=False):
    value = {
        "adapter_id": "mock",
        "request_id": f"R{seq}",
        "lease_id": "LEASE-X",
        "nonce": nonce,
        "sequence": seq,
        "principal": "agent",
        "objective_id": "inspect",
        "operation": "read",
        "target": target,
        "destination": target,
        "credential_ref": "read-token",
        "side_effect": side_effect,
        "timestamp": "2026-08-12T22:30:00Z",
        "parameters": {"path": "/record", "mode": "metadata"},
    }
    if with_contract:
        value["capability_contract_id"] = CAP_ID
    return value


class MockAdapter:
    adapter_id = "mock"

    def __init__(self, *, effective_target=None, effective_effect=None, cost=None, mutate_envelope=None, security_effects=None):
        self.effective_target = effective_target
        self.effective_effect = effective_effect
        self.cost = cost or {"actions": 1, "network_calls": 1, "egress_bytes": 10, "wall_clock_seconds": 1}
        self.mutate_envelope = mutate_envelope
        self.security_effects = security_effects
        self.executions = []

    def prepare(self, model_request):
        broker_request = {
            key: value for key, value in model_request.items()
            if key not in {"parameters", "usage"}
        }
        if self.effective_target is not None:
            broker_request["target"] = self.effective_target
            broker_request["destination"] = self.effective_target
        if self.effective_effect is not None:
            broker_request["side_effect"] = self.effective_effect
        if self.mutate_envelope is not None:
            field, value = self.mutate_envelope
            broker_request[field] = value
        return PreparedAction(
            adapter_id=self.adapter_id,
            broker_request=broker_request,
            parameters=model_request.get("parameters", {}),
            cost=self.cost,
            security_effects=self.security_effects,
        )

    def execute(self, action):
        self.executions.append(action)
        return {"ok": True, "target": action.broker_request["target"], "action_hash": action.action_hash}


class BindingDroppingBroker:
    """Test double representing an authorization layer that fails to bind the exact action."""

    def __init__(self, inner):
        self.inner = inner

    def authorize(self, request, *, cost, now=None, execution_binding_hash=None):
        return self.inner.authorize(request, cost=cost, now=now)


class MediatedExecutorTests(unittest.TestCase):
    def test_prepared_action_is_deeply_immutable(self):
        broker_request = {key: value for key, value in request().items() if key not in {"adapter_id", "parameters"}}
        action = PreparedAction(
            adapter_id="mock",
            broker_request=broker_request,
            parameters={"nested": {"value": 1}},
            cost={"actions": 1, "network_calls": 1, "egress_bytes": 0, "wall_clock_seconds": 1},
        )
        original_hash = action.action_hash
        broker_request["target"] = "sandbox://mutated"
        self.assertEqual(action.broker_request["target"], "sandbox://allowed")
        params = action.parameters
        params["nested"]["value"] = 999
        self.assertEqual(action.parameters["nested"]["value"], 1)
        self.assertEqual(action.action_hash, original_hash)
        with self.assertRaises(AttributeError):
            action._adapter_id = "other"

    def test_authorized_prepared_action_executes_and_binding_is_chained(self):
        adapter = MockAdapter()
        broker = EnforcementBroker(lease(), KEY)
        executor = MediatedExecutor(broker, {"mock": adapter})
        result = executor.execute(request(), now=NOW)
        self.assertEqual(result["decision"], "ALLOW")
        self.assertTrue(result["executed"])
        self.assertEqual(len(adapter.executions), 1)
        self.assertEqual(adapter.executions[0].action_hash, result["action_hash"])
        self.assertEqual(result["authorization_receipt"]["execution_binding_hash"], result["action_hash"])
        self.assertTrue(broker.verify_receipts())
        broker.receipts[0]["execution_binding_hash"] = "f" * 64
        self.assertFalse(broker.verify_receipts())

    def test_missing_broker_binding_blocks_execution(self):
        adapter = MockAdapter()
        executor = MediatedExecutor(BindingDroppingBroker(EnforcementBroker(lease(), KEY)), {"mock": adapter})
        result = executor.execute(request(), now=NOW)
        self.assertEqual(result["decision"], "DENY")
        self.assertEqual(result["reason"], "authorization_binding_mismatch")
        self.assertFalse(result["executed"])
        self.assertEqual(adapter.executions, [])

    def test_effective_target_not_model_claim_is_authorized(self):
        adapter = MockAdapter(effective_target="sandbox://blocked")
        executor = MediatedExecutor(EnforcementBroker(lease(), KEY), {"mock": adapter})
        result = executor.execute(request(target="sandbox://allowed"), now=NOW)
        self.assertEqual(result["decision"], "DENY")
        self.assertFalse(result["executed"])
        self.assertEqual(result["reason"], "target_scope")

    def test_adapter_side_effect_escalation_is_denied(self):
        adapter = MockAdapter(effective_effect="persistent_write")
        executor = MediatedExecutor(EnforcementBroker(lease(), KEY), {"mock": adapter})
        result = executor.execute(request(), now=NOW)
        self.assertEqual(result["decision"], "DENY")
        self.assertEqual(result["reason"], "side_effect_ceiling")

    def test_adapter_cost_controls_budget(self):
        adapter = MockAdapter(cost={"actions": 1, "network_calls": 2, "egress_bytes": 0, "wall_clock_seconds": 1})
        executor = MediatedExecutor(EnforcementBroker(lease(max_network_calls=1), KEY), {"mock": adapter})
        result = executor.execute(request(), now=NOW)
        self.assertEqual(result["decision"], "DENY")
        self.assertEqual(result["reason"], "network_budget")

    def test_model_supplied_usage_is_not_authoritative(self):
        r = request()
        r["usage"] = {"actions": 0, "network_calls": 0, "egress_bytes": 0, "wall_clock_seconds": 0}
        adapter = MockAdapter(cost={"actions": 1, "network_calls": 2, "egress_bytes": 0, "wall_clock_seconds": 1})
        executor = MediatedExecutor(EnforcementBroker(lease(max_network_calls=1), KEY), {"mock": adapter})
        result = executor.execute(r, now=NOW)
        self.assertEqual(result["decision"], "DENY")
        self.assertEqual(result["reason"], "network_budget")

    def test_adapter_cannot_change_replay_or_authority_identity(self):
        for field, value in [
            ("lease_id", "OTHER"),
            ("nonce", "other-nonce-00000"),
            ("sequence", 99),
            ("principal", "other-agent"),
            ("objective_id", "other-objective"),
            ("timestamp", "2026-08-12T22:00:00Z"),
        ]:
            with self.subTest(field=field):
                adapter = MockAdapter(mutate_envelope=(field, value))
                executor = MediatedExecutor(EnforcementBroker(lease(), KEY), {"mock": adapter})
                result = executor.execute(request(), now=NOW)
                self.assertEqual(result["decision"], "DENY")
                self.assertTrue(result["reason"].startswith("preparation_failed:"))

    def _executor_with_contract(self, adapter):
        return MediatedExecutor(
            EnforcementBroker(lease(with_contract=True), KEY),
            {"mock": adapter},
            {CAP_ID: capability_contract()},
        )

    def test_valid_capability_contract_allows_execution(self):
        adapter = MockAdapter()
        result = self._executor_with_contract(adapter).execute(request(with_contract=True), now=NOW)
        self.assertEqual(result["decision"], "ALLOW")
        self.assertTrue(result["executed"])

    def test_contract_denies_unapproved_parameter_value(self):
        adapter = MockAdapter()
        executor = self._executor_with_contract(adapter)
        r = request(with_contract=True)
        r["parameters"]["path"] = "/etc/passwd"
        result = executor.execute(r, now=NOW)
        self.assertEqual(result["decision"], "DENY")
        self.assertTrue(result["reason"].startswith("preparation_failed:"))

    def test_contract_denies_redirect_effect(self):
        adapter = MockAdapter(security_effects={
            "redirect_chain": ["sandbox://allowed"],
            "filesystem_paths": [],
            "subprocesses": [],
            "secondary_destinations": [],
        })
        result = self._executor_with_contract(adapter).execute(request(with_contract=True), now=NOW)
        self.assertEqual(result["decision"], "DENY")
        self.assertFalse(result["executed"])

    def test_contract_denies_filesystem_subprocess_and_secondary_effects(self):
        cases = [
            {"redirect_chain": [], "filesystem_paths": ["/tmp/x"], "subprocesses": [], "secondary_destinations": []},
            {"redirect_chain": [], "filesystem_paths": [], "subprocesses": ["sh"], "secondary_destinations": []},
            {"redirect_chain": [], "filesystem_paths": [], "subprocesses": [], "secondary_destinations": ["https://other.example"]},
        ]
        for effects in cases:
            with self.subTest(effects=effects):
                adapter = MockAdapter(security_effects=effects)
                result = self._executor_with_contract(adapter).execute(request(with_contract=True), now=NOW)
                self.assertEqual(result["decision"], "DENY")
                self.assertFalse(result["executed"])

    def test_contract_registry_requires_explicit_contract_id(self):
        adapter = MockAdapter()
        executor = self._executor_with_contract(adapter)
        result = executor.execute(request(with_contract=False), now=NOW)
        self.assertEqual(result["decision"], "DENY")
        self.assertFalse(result["executed"])

    def test_unknown_adapter_fails_before_authorization(self):
        adapter = MockAdapter()
        executor = MediatedExecutor(EnforcementBroker(lease(), KEY), {"mock": adapter})
        r = request()
        r["adapter_id"] = "missing"
        result = executor.execute(r, now=NOW)
        self.assertEqual(result["decision"], "DENY")
        self.assertIsNone(result["authorization_receipt"])


if __name__ == "__main__":
    unittest.main()
