from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.attack_graph import (
    AttackGraph,
    BlastRadiusAnalyzer,
    InfrastructureTopology,
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

    topology = InfrastructureTopology.model_validate(
        payload
    )

    graph = AttackGraph()

    graph.load(
        topology.nodes,
        topology.edges,
    )

    return graph


def test_dfs_calculates_full_blast_radius() -> None:
    graph = build_graph()
    analyzer = BlastRadiusAnalyzer(graph)

    result = analyzer.analyse(
        source_id="USR-104"
    )

    assert result.source_id == "USR-104"
    assert result.reachable_node_count >= 8
    assert result.critical_node_count >= 4
    assert result.maximum_depth >= 3
    assert result.cumulative_business_impact > 0
    assert result.blast_radius_score > 0

    assert "EXAM-APP-01" in result.critical_assets_at_risk
    assert "EXAM-DB-01" in result.critical_assets_at_risk
    assert "QUESTION-REPO-01" in result.critical_assets_at_risk


def test_depth_limited_blast_radius() -> None:
    graph = build_graph()
    analyzer = BlastRadiusAnalyzer(graph)

    result = analyzer.analyse(
        source_id="USR-104",
        maximum_depth=2,
    )

    assert result.maximum_depth <= 2

    reachable_ids = {
        node.node_id
        for node in result.reachable_nodes
    }

    assert "USR-104" in reachable_ids
    assert "DEV-018" in reachable_ids
    assert "IDP-001" in reachable_ids
    assert "EXAM-DB-01" not in reachable_ids


def test_excluding_source_node() -> None:
    graph = build_graph()
    analyzer = BlastRadiusAnalyzer(graph)

    result = analyzer.analyse(
        source_id="USR-104",
        include_source=False,
    )

    reachable_ids = {
        node.node_id
        for node in result.reachable_nodes
    }

    assert "USR-104" not in reachable_ids
    assert "DEV-018" in reachable_ids


def test_unknown_source_is_rejected() -> None:
    graph = build_graph()
    analyzer = BlastRadiusAnalyzer(graph)

    with pytest.raises(
        KeyError,
        match="Node not found",
    ):
        analyzer.analyse(
            source_id="UNKNOWN-NODE"
        )


def test_negative_depth_is_rejected() -> None:
    graph = build_graph()
    analyzer = BlastRadiusAnalyzer(graph)

    with pytest.raises(
        ValueError,
        match="maximum_depth cannot be negative",
    ):
        analyzer.analyse(
            source_id="USR-104",
            maximum_depth=-1,
        )


def test_multiple_source_analysis() -> None:
    graph = build_graph()
    analyzer = BlastRadiusAnalyzer(graph)

    results = analyzer.analyse_multiple_sources(
        source_ids=[
            "USR-104",
            "DEV-018",
        ]
    )

    assert set(results) == {
        "USR-104",
        "DEV-018",
    }

    assert (
        results["USR-104"].reachable_node_count
        >= results["DEV-018"].reachable_node_count
    )


def test_containment_reduces_blast_radius() -> None:
    graph = build_graph()
    analyzer = BlastRadiusAnalyzer(graph)

    comparison = analyzer.compare_after_containment(
        source_id="USR-104",
        connections_to_disable=[
            (
                "DEV-018",
                "EXAM-APP-01",
            ),
            (
                "DEV-018",
                "IDP-001",
            ),
            (
                "DEV-018",
                "PORTAL-001",
            ),
        ],
    )

    assert (
        comparison.before.reachable_node_count
        > comparison.after.reachable_node_count
    )

    assert comparison.removed_reachable_nodes > 0
    assert comparison.blast_radius_reduction > 0

    assert (
        "DEV-018->EXAM-APP-01"
        in comparison.disabled_connections
    )


def test_single_edge_containment_leaves_alternate_path() -> None:
    graph = build_graph()
    analyzer = BlastRadiusAnalyzer(graph)

    comparison = analyzer.compare_after_containment(
        source_id="USR-104",
        connections_to_disable=[
            (
                "DEV-018",
                "EXAM-APP-01",
            )
        ],
    )

    after_ids = {
        node.node_id
        for node in comparison.after.reachable_nodes
    }

    assert "EXAM-APP-01" in after_ids