#!/usr/bin/env python3
"""Adapter-specific capability contracts for AAB mediated execution.

A capability contract constrains the *effective* prepared action, including
security-relevant parameters and secondary effects. It does not trust command
text or model intent. Correctness still depends on the trusted adapter reporting
its effective behavior accurately and on complete mediation of equivalent paths.
"""
from __future__ import annotations

from typing import Any, Mapping, Protocol


class CapabilityContractError(RuntimeError):
    pass


_EFFECT_KEYS = {
    "redirect_chain",
    "filesystem_paths",
    "subprocesses",
    "secondary_destinations",
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
    return list(value)


def validate_contract(contract: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(contract, Mapping):
        raise CapabilityContractError("contract must be an object")
    required = {
        "contract_id",
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
        "allowed_secondary_destinations",
    }
    missing = required - set(contract)
    if missing:
        raise CapabilityContractError(f"contract missing:{','.join(sorted(missing))}")
    if not isinstance(contract["contract_id"], str) or not contract["contract_id"]:
        raise CapabilityContractError("invalid contract_id")
    if not isinstance(contract["adapter_id"], str) or not contract["adapter_id"]:
        raise CapabilityContractError("invalid adapter_id")
    if not isinstance(contract["operation"], str) or not contract["operation"]:
        raise CapabilityContractError("invalid operation")

    normalized = dict(contract)
    for field in (
        "allowed_parameter_keys",
        "required_parameter_keys",
        "allowed_effective_destinations",
        "allowed_credentials",
        "allowed_filesystem_paths",
        "allowed_secondary_destinations",
    ):
        normalized[field] = _list_of_strings(contract[field], field)

    if not set(normalized["required_parameter_keys"]).issubset(set(normalized["allowed_parameter_keys"])):
        raise CapabilityContractError("required_parameter_keys must be a subset of allowed_parameter_keys")

    allowlists = contract["parameter_allowlists"]
    if not isinstance(allowlists, Mapping):
        raise CapabilityContractError("parameter_allowlists must be an object")
    for key, values in allowlists.items():
        if key not in normalized["allowed_parameter_keys"]:
            raise CapabilityContractError("parameter_allowlist key is not allowed")
        if not isinstance(values, list) or not values:
            raise CapabilityContractError("parameter allowlists must be non-empty arrays")
        for value in values:
            if isinstance(value, (dict, list)):
                raise CapabilityContractError("parameter allowlist values must be JSON scalars")
    normalized["parameter_allowlists"] = {key: list(values) for key, values in allowlists.items()}

    for flag in ("allow_redirects", "allow_subprocess"):
        if not isinstance(contract[flag], bool):
            raise CapabilityContractError(f"{flag} must be boolean")
    return normalized


def validate_prepared_action(contract: Mapping[str, Any], action: PreparedLike) -> None:
    c = validate_contract(contract)
    request = action.broker_request
    parameters = action.parameters
    effects = action.security_effects

    if action.adapter_id != c["adapter_id"]:
        raise CapabilityContractError("adapter_id does not match capability contract")
    if request.get("operation") != c["operation"]:
        raise CapabilityContractError("operation does not match capability contract")
    if request.get("capability_contract_id") != c["contract_id"]:
        raise CapabilityContractError("broker request is not bound to capability contract")

    if not isinstance(parameters, dict):
        raise CapabilityContractError("contracted parameters must be an object")
    keys = set(parameters)
    allowed_keys = set(c["allowed_parameter_keys"])
    required_keys = set(c["required_parameter_keys"])
    if not keys.issubset(allowed_keys):
        raise CapabilityContractError("unapproved parameter key")
    if not required_keys.issubset(keys):
        raise CapabilityContractError("required parameter missing")
    for key, allowed_values in c["parameter_allowlists"].items():
        if key in parameters and parameters[key] not in allowed_values:
            raise CapabilityContractError(f"parameter value denied:{key}")

    destination = request.get("destination")
    if destination is not None and destination not in c["allowed_effective_destinations"]:
        raise CapabilityContractError("effective destination denied by capability contract")
    credential = request.get("credential_ref")
    if credential is not None and credential not in c["allowed_credentials"]:
        raise CapabilityContractError("credential denied by capability contract")

    if not isinstance(effects, dict) or set(effects) != _EFFECT_KEYS:
        raise CapabilityContractError("security_effects must contain exactly the required effect classes")
    normalized_effects = {key: _list_of_strings(effects[key], key) for key in _EFFECT_KEYS}

    if normalized_effects["redirect_chain"]:
        if not c["allow_redirects"]:
            raise CapabilityContractError("redirects are not authorized")
        for destination in normalized_effects["redirect_chain"]:
            if destination not in c["allowed_effective_destinations"]:
                raise CapabilityContractError("redirect destination denied")

    for path in normalized_effects["filesystem_paths"]:
        if path not in c["allowed_filesystem_paths"]:
            raise CapabilityContractError("filesystem effect denied")

    if normalized_effects["subprocesses"] and not c["allow_subprocess"]:
        raise CapabilityContractError("subprocess effect denied")

    for destination in normalized_effects["secondary_destinations"]:
        if destination not in c["allowed_secondary_destinations"]:
            raise CapabilityContractError("secondary network effect denied")
