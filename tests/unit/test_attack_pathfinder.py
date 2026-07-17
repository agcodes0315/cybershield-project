from __future__ import annotations

import json
from pathlib import Path

from app.attack_graph.graph import (
    AttackGraph,
)
from app.attack_graph.pathfinder import (
    AttackPathfinder,
)
from app.attack_graph.schemas import (
    InfrastructureTopology,
    PathAlgorithm,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]

TOPOLOGY_PATH = (
    PROJECT_ROOT
    / "event-simulator"
    / "datasets"
    / "infrastructure_topology.json"
)


def build_graph() -> AttackGraph:
    with TOPOLOGY_PATH.open(
        "r",
        encoding="utf-8",
    ) as file:
        payload = json.load(file)

    topology = (
        InfrastructureTopology.model_validate(
            payload
        )
    )

    graph = AttackGraph()

    graph.load(
        topology.nodes,
        topology.edges,
    )

    return graph


def test_bfs_finds_minimum_hop_path() -> None:
    graph = build_graph()
    pathfinder = AttackPathfinder(graph)

    result = pathfinder.shortest_hop_path(
        "USR-104",
        "EXAM-DB-01",
    )

    assert result.found is True
    assert result.algorithm == PathAlgorithm.BFS

    assert result.node_ids == [
        "USR-104",
        "DEV-018",
        "EXAM-APP-01",
        "EXAM-DB-01",
    ]

    assert result.hop_count == 3
    assert result.total_cost > 0
    assert result.path_risk_score > 0


def test_dijkstra_finds_lowest_cost_path() -> None:
    graph = build_graph()
    pathfinder = AttackPathfinder(graph)

    result = (
        pathfinder.lowest_resistance_path(
            "USR-104",
            "EXAM-DB-01",
        )
    )

    assert result.found is True
    assert result.algorithm == (
        PathAlgorithm.DIJKSTRA
    )

    assert result.node_ids[0] == "USR-104"
    assert result.node_ids[-1] == (
        "EXAM-DB-01"
    )

    assert result.hop_count >= 3
    assert result.total_cost > 0
    assert result.controls_encountered


def test_nearest_critical_asset() -> None:
    graph = build_graph()
    pathfinder = AttackPathfinder(graph)

    result = pathfinder.nearest_critical_asset(
        source_id="USR-104",
        algorithm=PathAlgorithm.DIJKSTRA,
    )

    assert result.found is True
    assert result.target_id is not None
    assert result.path is not None

    assert result.path.node_ids[0] == (
        "USR-104"
    )

    assert result.target_id in {
        "IDP-001",
        "EXAM-APP-01",
        "EXAM-DB-01",
        "QUESTION-REPO-01",
        "SOC-001",
    }


def test_all_reachable_critical_paths() -> None:
    graph = build_graph()
    pathfinder = AttackPathfinder(graph)

    paths = (
        pathfinder.all_reachable_critical_paths(
            source_id="USR-104",
            algorithm=PathAlgorithm.DIJKSTRA,
        )
    )

    target_ids = {
        path.target_id
        for path in paths
    }

    assert "IDP-001" in target_ids
    assert "EXAM-APP-01" in target_ids
    assert "EXAM-DB-01" in target_ids
    assert "QUESTION-REPO-01" in target_ids

    costs = [
        path.total_cost
        for path in paths
    ]

    assert costs == sorted(costs)


def test_disabled_edge_changes_bfs_path() -> None:
    graph = build_graph()
    pathfinder = AttackPathfinder(graph)

    original = pathfinder.shortest_hop_path(
        "USR-104",
        "EXAM-DB-01",
    )

    assert "EXAM-APP-01" in (
        original.node_ids
    )

    changed = graph.disable_edge(
        "DEV-018",
        "EXAM-APP-01",
    )

    assert changed == 1

    updated = pathfinder.shortest_hop_path(
        "USR-104",
        "EXAM-DB-01",
    )

    assert updated.found is True

    assert updated.node_ids == [
        "USR-104",
        "DEV-018",
        "IDP-001",
        "EXAM-APP-01",
        "EXAM-DB-01",
    ]


def test_unreachable_path_returns_not_found() -> None:
    graph = build_graph()
    pathfinder = AttackPathfinder(graph)

    result = pathfinder.shortest_hop_path(
        "EXAM-DB-01",
        "SOC-001",
    )

    assert result.found is False
    assert result.node_ids == []
    assert result.hop_count == 0
    assert "No enabled path exists" in (
        result.explanation
    )


def test_source_equals_target() -> None:
    graph = build_graph()
    pathfinder = AttackPathfinder(graph)

    result = (
        pathfinder.lowest_resistance_path(
            "DEV-018",
            "DEV-018",
        )
    )

    assert result.found is True
    assert result.hop_count == 0
    assert result.node_ids == ["DEV-018"]