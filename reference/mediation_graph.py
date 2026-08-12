#!/usr/bin/env python3
"""Static mediation-graph verifier for AMAS AAB 0.4.

The graph is deliberately abstract. It models whether any path from an acting
agent to a side-effect sink can avoid an AAB enforcement broker. It does not
execute tools, network operations, exploits, or external side effects.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any

ALLOWED_NODE_TYPES = {"agent", "broker", "adapter", "proxy", "side_effect", "observer"}


def _validate_graph(graph: dict[str, Any]) -> tuple[dict[str, str], dict[str, list[str]]]:
    nodes = graph.get("nodes")
    edges = graph.get("edges")
    if not isinstance(nodes, dict) or not nodes:
        raise ValueError("nodes must be a non-empty object")
    if not isinstance(edges, list):
        raise ValueError("edges must be an array")
    node_types: dict[str, str] = {}
    for name, node_type in nodes.items():
        if not isinstance(name, str) or not name:
            raise ValueError("node names must be non-empty strings")
        if node_type not in ALLOWED_NODE_TYPES:
            raise ValueError(f"unsupported node type:{node_type}")
        node_types[name] = node_type

    adjacency: dict[str, list[str]] = defaultdict(list)
    for edge in edges:
        if not isinstance(edge, list) or len(edge) != 2:
            raise ValueError("each edge must be [source, destination]")
        source, destination = edge
        if source not in node_types or destination not in node_types:
            raise ValueError("edge references unknown node")
        adjacency[source].append(destination)
    return node_types, adjacency


def _paths_to_sinks(
    start: str,
    node_types: dict[str, str],
    adjacency: dict[str, list[str]],
) -> list[list[str]]:
    paths: list[list[str]] = []

    def walk(node: str, path: list[str], seen: set[str]) -> None:
        if node_types[node] == "side_effect":
            paths.append(path)
            return
        for nxt in adjacency.get(node, []):
            if nxt in seen:
                continue
            walk(nxt, path + [nxt], seen | {nxt})

    walk(start, [start], {start})
    return paths


def verify_mediation_graph(graph: dict[str, Any]) -> dict[str, Any]:
    """Prove that every modeled agent→side-effect path crosses a broker."""
    try:
        node_types, adjacency = _validate_graph(graph)
    except (TypeError, ValueError) as exc:
        return {"valid": False, "reason": f"invalid_graph:{exc}", "mediated_paths": [], "bypass_paths": []}

    agents = [name for name, node_type in node_types.items() if node_type == "agent"]
    sinks = [name for name, node_type in node_types.items() if node_type == "side_effect"]
    if not agents:
        return {"valid": False, "reason": "no_agent", "mediated_paths": [], "bypass_paths": []}
    if not sinks:
        return {"valid": False, "reason": "no_side_effect_sink", "mediated_paths": [], "bypass_paths": []}

    mediated: list[list[str]] = []
    bypass: list[list[str]] = []
    reachable = 0
    for agent in agents:
        for path in _paths_to_sinks(agent, node_types, adjacency):
            reachable += 1
            # A broker must occur strictly before the terminal side-effect sink.
            if any(node_types[node] == "broker" for node in path[:-1]):
                mediated.append(path)
            else:
                bypass.append(path)

    # No modeled agent-to-effect path is safe from bypass evidence, but it is
    # also not evidence of a functional mediated architecture. Report it
    # separately rather than silently calling the topology valid.
    if reachable == 0:
        return {
            "valid": False,
            "reason": "no_reachable_side_effect_path",
            "mediated_paths": [],
            "bypass_paths": [],
        }

    return {
        "valid": not bypass,
        "reason": "all_paths_mediated" if not bypass else "bypass_path_detected",
        "mediated_paths": mediated,
        "bypass_paths": bypass,
        "agent_count": len(agents),
        "sink_count": len(sinks),
        "reachable_path_count": reachable,
    }
