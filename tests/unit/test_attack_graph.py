from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.attack_graph.graph import AttackGraph
from app.attack_graph.schemas import (
    AssetCriticality,
    AttackGraphEdge,
    AttackGraphNode,
    ConnectionType,
    GraphNodeType,
    InfrastructureTopology,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]

TOPOLOGY_PATH = (
    PROJECT_ROOT
    / "event-simulator"
    / "datasets"
    / "infrastructure_topology.json"
)


def load_topology() -> InfrastructureTopology:
    with TOPOLOGY_PATH.open(
        "r",
        encoding="utf-8",
    ) as file:
        payload = json.load(file)

    return InfrastructureTopology.model_validate(
        payload
    )


def test_add_and_lookup_nodes() -> None:
    graph = AttackGraph()

    node = AttackGraphNode(
        node_id="NODE-001",
        name="Test Application",
        node_type=GraphNodeType.APPLICATION,
        criticality=AssetCriticality.HIGH,
        exposure_score=0.5,
        vulnerability_score=0.4,
        business_impact_score=0.8,
    )

    graph.add_node(node)

    stored = graph.get_node("NODE-001")

    assert stored is not None
    assert stored.name == "Test Application"
    assert stored.risk_score > 0.0


def test_duplicate_node_is_rejected() -> None:
    graph = AttackGraph()

    node = AttackGraphNode(
        node_id="NODE-001",
        name="Test Node",
        node_type=GraphNodeType.SERVER,
        criticality=AssetCriticality.MEDIUM,
    )

    graph.add_node(node)

    with pytest.raises(
        ValueError,
        match="Node already exists",
    ):
        graph.add_node(node)


def test_edge_requires_existing_nodes() -> None:
    graph = AttackGraph()

    graph.add_node(
        AttackGraphNode(
            node_id="NODE-001",
            name="Source",
            node_type=GraphNodeType.SERVER,
            criticality=AssetCriticality.MEDIUM,
        )
    )

    with pytest.raises(
        ValueError,
        match="target node does not exist",
    ):
        graph.add_edge(
            AttackGraphEdge(
                source_id="NODE-001",
                target_id="MISSING",
                connection_type=(
                    ConnectionType.CONNECTS_TO
                ),
            )
        )


def test_load_synthetic_topology() -> None:
    topology = load_topology()
    graph = AttackGraph()

    graph.load(
        topology.nodes,
        topology.edges,
    )

    statistics = graph.statistics()

    assert statistics.node_count == 9
    assert statistics.edge_count == 13
    assert statistics.critical_node_count == 5
    assert statistics.compromised_node_count == 2

    assert graph.contains_node("EXAM-DB-01")
    assert graph.contains_edge(
        "EXAM-APP-01",
        "EXAM-DB-01",
    )


def test_adjacency_lookup() -> None:
    topology = load_topology()
    graph = AttackGraph()

    graph.load(
        topology.nodes,
        topology.edges,
    )

    neighbours = graph.neighbours(
        "DEV-018"
    )

    neighbour_ids = {
        relationship.node.node_id
        for relationship in neighbours
    }

    assert "IDP-001" in neighbour_ids
    assert "PORTAL-001" in neighbour_ids
    assert "EXAM-APP-01" in neighbour_ids


def test_mark_node_compromised() -> None:
    topology = load_topology()
    graph = AttackGraph()

    graph.load(
        topology.nodes,
        topology.edges,
    )

    graph.mark_compromised(
        "EXAM-APP-01"
    )

    compromised_ids = {
        node.node_id
        for node in graph.compromised_nodes()
    }

    assert "EXAM-APP-01" in compromised_ids


def test_disable_edge() -> None:
    topology = load_topology()
    graph = AttackGraph()

    graph.load(
        topology.nodes,
        topology.edges,
    )

    changed = graph.disable_edge(
        "DEV-018",
        "EXAM-APP-01",
    )

    assert changed == 1

    enabled_neighbours = {
        relationship.node.node_id
        for relationship in graph.neighbours(
            "DEV-018",
            enabled_only=True,
        )
    }

    assert "EXAM-APP-01" not in (
        enabled_neighbours
    )