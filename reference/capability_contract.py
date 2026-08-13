#!/usr/bin/env python3
"""Adapter-specific capability contracts for AAB mediated execution.

A capability contract constrains the effective prepared action, including
security-relevant parameters and secondary effects. Contract identities are
content-addressed under Canonical JSON v1 so a policy cannot silently retain the
same capability name while its semantics change.
"""
from __future__ import annotations

import copy
from typing import Any, Mapping, Protocol

from canonical_json import CanonicalJSONError, sha256 as canonical_sha256, validate as validate_canonical


class CapabilityContractError(RuntimeError):
    pass


_EFFECT_KEYS = {
    "redirect_chain",
    "filesystem_paths",
    "subprocesses",
    "secondary_destinations",
}

_REQUIRED_BODY_FIELDS = {
    "adapter_id",
    "operation",
    "allowed_parameter_keys",
    "required_parameter_keys",
    "parameter_allowlists",
    "allowed_effective_destinations",
    "allowed_credentials",
    "allow_redirects",
    "allowed_filesystem_paths",
    "allow_subprocess",
    "allowed_subprocesses",
    "allowed_secondary_destinations",
}


class PreparedLike(Protocol):
    adapter_id: str

    @property
    def broker_request(self) -> dict[str, Any]: ...

    @property
    def parameters(self) -> Any: ...

    @property
    def security_effects(self) -> dict[str, list[str]]: ...


def _list_of_strings(value: Any, name: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise CapabilityContractError(f"{name} must be an array of non-empty strings")
    if len(value) != len(set(value)):
        raise CapabilityContractError(f"{name} must not contain duplicates")
    return list(value)


def _body(contract: Mapping[str, Any]) -> dict[str, Any]:
    return {key: copy.deepcopy(value) for key, value in contract.items() if key != "contract_id"}


def _normalize_body(body: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(body, Mapping):
        raise CapabilityContractError("contract must be an object")
    normalized = copy.deepcopy(dict(body))
    normalized.setdefault("unrestricted_parameter_keys", [])
    normalized.setdefault("allowed_subprocesses", [])

    missing = _REQUIRED_BODY_FIELDS - set(normalized)
    if missing:
        raise CapabilityContractError(f"contract missing:{','.join(sorted(missing))}")
    allowed_fields = _REQUIRED_BODY_FIELDS | {"unrestricted_parameter_keys"}
    extra = set(normalized) - allowed_fields
    if extra:
        raise CapabilityContractError(f"contract has unknown fields:{','.join(sorted(extra))}")

    for field in (
        "adapter_id",
        "operation",
    ):
        if not isinstance(normalized[field], str) or not normalized[field]:
            raise CapabilityContractError(f"invalid {field}")

    for field in (
        "allowed_parameter_keys",
        "required_parameter_keys",
        "unrestricted_parameter_keys",
        "allowed_effective_destinations",
        "allowed_credentials",
        "allowed_filesystem_paths",
        "allowed_subprocesses",
        "allowed_secondary_destinations",
    ):
        normalized[field] = _list_of_strings(normalized[field], field)

    allowed_keys = set(normalized["allowed_parameter_keys"])
    required_keys = set(normalized["required_parameter_keys"])
    unrestricted = set(normalized["unrestricted_parameter_keys"])
    if not required_keys.issubset(allowed_keys):
        raise CapabilityContractError("required_parameter_keys must be a subset of allowed_parameter_keys")
    if not unrestricted.issubset(allowed_keys):
        raise CapabilityContractError("unrestricted_parameter_keys must be a subset of allowed_parameter_keys")

    allowlists = normalized["parameter_allowlists"]
    if not isinstance(allowlists, Mapping):
        raise CapabilityContractError("parameter_allowlists must be an object")
    normalized_lists: dict[str, list[Any]] = {}
    for key, values in allowlists.items():
        if not isinstance(key, str) or not key or key not in allowed_keys:
            raise CapabilityContractError("parameter_allowlist key is not allowed")
        if not isinstance(values, list) or not values:
            raise CapabilityContractError("parameter allowlists must be non-empty arrays")
        for value in values:
            if isinstance(value, (dict, list)):
                raise CapabilityContractError("parameter allowlist values must be JSON scalars")
            try:
                validate_canonical(value)
            except CanonicalJSONError as exc:
                raise CapabilityContractError("parameter allowlist contains non-canonical value") from exc
        # Canonical identity rather than Python equality catches True vs 1.
        identities = [canonical_sha256(value) for value in values]
        if len(identities) != len(set(identities)):
            raise CapabilityContractError("parameter allowlist contains duplicate canonical values")
        normalized_lists[key] = copy.deepcopy(values)
    normalized["parameter_allowlists"] = normalized_lists

    controlled = set(normalized_lists) | unrestricted
    if controlled != allowed_keys:
        missing_controls = sorted(allowed_keys - controlled)
        raise CapabilityContractError("every allowed parameter must be allowlisted or explicitly unrestricted:" + ",".join(missing_controls))
    if set(normalized_lists) & unrestricted:
        raise CapabilityContractError("parameter cannot be both allowlisted and unrestricted")

    for flag in ("allow_redirects", "allow_subprocess"):
        if not isinstance(normalized[flag], bool):
            raise CapabilityContractError(f"{flag} must be boolean")
    if not normalized["allow_subprocess"] and normalized["allowed_subprocesses"]:
        raise CapabilityContractError("allowed_subprocesses must be empty when subprocesses are disabled")

    try:
        validate_canonical(normalized)
    except CanonicalJSONError as exc:
        raise CapabilityContractError("contract body is not Canonical JSON v1") from exc
    return normalized


def bind_contract_id(contract_body: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize a contract body and attach its content-addressed identity."""
    body = _normalize_body(contract_body)
    result = copy.deepcopy(body)
    result["contract_id"] = "cap-sha256:" + canonical_sha256(body)
    return result


def verify_contract_identity(contract: Mapping[str, Any]) -> bool:
    try:
        if not isinstance(contract, Mapping):
            return False
        contract_id = contract.get("contract_id")
        if not isinstance(contract_id, str) or not contract_id.startswith("cap-sha256:") or len(contract_id) != len("cap-sha256:") + 64:
            return False
        body = _normalize_body(_body(contract))
        return contract_id == "cap-sha256:" + canonical_sha256(body)
    except (CapabilityContractError, CanonicalJSONError, TypeError, ValueError, RecursionError):
        return False


def _scalar_equal(left: Any, right: Any) -> bool:
    # Python considers True == 1. Authority allowlists must not.
    return type(left) is type(right) and left == right


def _validate_effective_action(
    contract: Mapping[str, Any],
    *,
    adapter_id: str,
    broker_request: Mapping[str, Any],
    parameters: Any,
    security_effects: Mapping[str, Any] | None,
) -> dict[str, Any]:
    try:
        if not verify_contract_identity(contract):
            raise CapabilityContractError("contract identity mismatch")
        c = dict(contract)
        body = _normalize_body(_body(c))

        if adapter_id != body["adapter_id"]:
            return {"valid": False, "reason": "contract_adapter_id"}
        if not isinstance(broker_request, Mapping):
            return {"valid": False, "reason": "contract_broker_request"}
        if broker_request.get("operation") != body["operation"]:
            return {"valid": False, "reason": "contract_operation"}
        if broker_request.get("capability_contract_id") not in (None, c["contract_id"]):
            return {"valid": False, "reason": "contract_identity_binding"}

        if not isinstance(parameters, dict):
            return {"valid": False, "reason": "contract_parameters"}
        validate_canonical(parameters)
        keys = set(parameters)
        allowed_keys = set(body["allowed_parameter_keys"])
        required_keys = set(body["required_parameter_keys"])
        if not keys.issubset(allowed_keys):
            return {"valid": False, "reason": "contract_parameter_key"}
        if not required_keys.issubset(keys):
            return {"valid": False, "reason": "contract_required_parameter"}
        for key, allowed_values in body["parameter_allowlists"].items():
            if key in parameters and not any(_scalar_equal(parameters[key], candidate) for candidate in allowed_values):
                return {"valid": False, "reason": f"contract_parameter_value:{key}"}

        destination = broker_request.get("destination")
        if destination is not None and destination not in body["allowed_effective_destinations"]:
            return {"valid": False, "reason": "contract_effective_destination"}
        credential = broker_request.get("credential_ref")
        if credential is not None and credential not in body["allowed_credentials"]:
            return {"valid": False, "reason": "contract_credential"}

        effects = {
            "redirect_chain": [],
            "filesystem_paths": [],
            "subprocesses": [],
            "secondary_destinations": [],
        } if security_effects is None else copy.deepcopy(dict(security_effects))
        if set(effects) != _EFFECT_KEYS:
            return {"valid": False, "reason": "contract_security_effect_shape"}
        for key in _EFFECT_KEYS:
            effects[key] = _list_of_strings(effects[key], key)

        if effects["redirect_chain"]:
            if not body["allow_redirects"]:
                return {"valid": False, "reason": "contract_redirect"}
            for destination in effects["redirect_chain"]:
                if destination not in body["allowed_effective_destinations"]:
                    return {"valid": False, "reason": "contract_redirect_destination"}

        for path in effects["filesystem_paths"]:
            if path not in body["allowed_filesystem_paths"]:
                return {"valid": False, "reason": "contract_filesystem_path"}

        if effects["subprocesses"]:
            if not body["allow_subprocess"]:
                return {"valid": False, "reason": "contract_subprocess"}
            for process in effects["subprocesses"]:
                if process not in body["allowed_subprocesses"]:
                    return {"valid": False, "reason": "contract_subprocess_name"}

        for destination in effects["secondary_destinations"]:
            if destination not in body["allowed_secondary_destinations"]:
                return {"valid": False, "reason": "contract_secondary_destination"}

        return {"valid": True, "reason": "authorized_contract"}
    except (CapabilityContractError, CanonicalJSONError, TypeError, ValueError, RecursionError) as exc:
        return {"valid": False, "reason": f"invalid_contract:{type(exc).__name__}"}


def validate_contract(
    contract: Mapping[str, Any],
    *,
    adapter_id: str,
    broker_request: Mapping[str, Any],
    parameters: Any,
    security_effects: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Return a fail-closed validation result for one effective action."""
    return _validate_effective_action(
        contract,
        adapter_id=adapter_id,
        broker_request=broker_request,
        parameters=parameters,
        security_effects=security_effects,
    )


def validate_prepared_action(contract: Mapping[str, Any], action: PreparedLike) -> None:
    request = action.broker_request
    if request.get("capability_contract_id") != contract.get("contract_id"):
        raise CapabilityContractError("broker request is not bound to capability contract")
    result = _validate_effective_action(
        contract,
        adapter_id=action.adapter_id,
        broker_request=request,
        parameters=action.parameters,
        security_effects=action.security_effects,
    )
    if not result["valid"]:
        raise CapabilityContractError(result["reason"])
