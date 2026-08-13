#!/usr/bin/env python3
"""Static mediation-graph verifier for AMAS AAB 0.4.

The verifier treats bypass as a graph reachability property rather than
enumerating every simple path. For each agent, it performs bounded breadth-first
search in the full graph and in a graph with broker nodes removed. If a
side-effect sink is reachable after brokers are removed, a bypass exists.

This avoids exponential path enumeration while retaining shortest witness paths.
It does not execute tools, network operations, exploits, or side effects.
"""
from __future__ import annotations

from collections import defaultdict, deque
from typing import Any, Iterable

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

    # Stable traversal makes witnesses deterministic across implementations.
    for source in adjacency:
        adjacency[source] = sorted(set(adjacency[source]))
    return node_types, adjacency


def _shortest_paths(
    start: str,
    adjacency: dict[str, list[str]],
    *,
    blocked: Iterable[str] = (),
) -> dict[str, list[str]]:
    """Return one deterministic shortest path from start to each reachable node."""
    blocked_set = set(blocked)
    blocked_set.discard(start)
    paths: dict[str, list[str]] = {start: [start]}
    queue = deque([start])
    while queue:
        node = queue.popleft()
        for nxt in adjacency.get(node, []):
            if nxt in blocked_set or nxt in paths:
                continue
            paths[nxt] = paths[node] + [nxt]
            queue.append(nxt)
    return paths


def verify_mediation_graph(graph: dict[str, Any]) -> dict[str, Any]:
    """Verify that every modeled agent→side-effect reachability route needs a broker.

    Security condition: removing all broker nodes must disconnect every agent
    from every side-effect sink. Shortest full-graph and bypass witnesses are
    returned for review.
    """
    try:
        node_types, adjacency = _validate_graph(graph)
    except (TypeError, ValueError) as exc:
        return {"valid": False, "reason": f"invalid_graph:{exc}", "mediated_paths": [], "bypass_paths": []}

    agents = sorted(name for name, node_type in node_types.items() if node_type == "agent")
    sinks = sorted(name for name, node_type in node_types.items() if node_type == "side_effect")
    brokers = {name for name, node_type in node_types.items() if node_type == "broker"}

    if not agents:
        return {"valid": False, "reason": "no_agent", "mediated_paths": [], "bypass_paths": []}
    if not sinks:
        return {"valid": False, "reason": "no_side_effect_sink", "mediated_paths": [], "bypass_paths": []}

    mediated: list[list[str]] = []
    bypass: list[list[str]] = []
    reachable_pairs = 0

    for agent in agents:
        full_paths = _shortest_paths(agent, adjacency)
        brokerless_paths = _shortest_paths(agent, adjacency, blocked=brokers)
        for sink in sinks:
            full = full_paths.get(sink)
            if full is None:
                continue
            reachable_pairs += 1
            bypass_path = brokerless_paths.get(sink)
            if bypass_path is not None:
                bypass.append(bypass_path)
            else:
                mediated.append(full)

    if reachable_pairs == 0:
        return {
            "valid": False,
            "reason": "no_reachable_side_effect_path",
            "mediated_paths": [],
            "bypass_paths": [],
            "agent_count": len(agents),
            "sink_count": len(sinks),
            "reachable_path_count": 0,
        }

    return {
        "valid": not bypass,
        "reason": "all_paths_mediated" if not bypass else "bypass_path_detected",
        "mediated_paths": mediated,
        "bypass_paths": bypass,
        "agent_count": len(agents),
        "sink_count": len(sinks),
        # Kept for backward compatibility; now counts reachable agent/sink pairs,
        # not all simple paths (which can be exponential).
        "reachable_path_count": reachable_pairs,
    }
