from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.attack_graph import (
    AttackGraph,
    InfrastructureTopology,
    RemediationActionType,
    RemediationPrioritizer,
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


def test_generate_remediation_plan() -> None:
    graph = build_graph()
    prioritizer = RemediationPrioritizer(graph)

    plan = prioritizer.generate_plan(
        source_id="USR-104"
    )

    assert plan.source_id == "USR-104"
    assert plan.candidate_count > 0
    assert plan.recommended_action_count > 0
    assert plan.top_recommendation is not None
    assert plan.candidates


def test_candidates_are_sorted_by_priority() -> None:
    graph = build_graph()
    prioritizer = RemediationPrioritizer(graph)

    plan = prioritizer.generate_plan(
        source_id="USR-104"
    )

    priority_scores = [
        candidate.priority_score
        for candidate in plan.candidates
    ]

    assert priority_scores == sorted(
        priority_scores,
        reverse=True,
    )

    ranks = [
        candidate.rank
        for candidate in plan.candidates
    ]

    assert ranks == list(
        range(
            1,
            len(plan.candidates) + 1,
        )
    )


def test_top_recommendation_reduces_blast_radius() -> None:
    graph = build_graph()
    prioritizer = RemediationPrioritizer(graph)

    plan = prioritizer.generate_plan(
        source_id="USR-104"
    )

    top = plan.top_recommendation

    assert top is not None
    assert top.blast_radius_reduction > 0
    assert top.reachable_nodes_removed > 0
    assert top.effectiveness_score > 0
    assert top.priority_score > 0


def test_node_isolation_candidates_are_created() -> None:
    graph = build_graph()
    prioritizer = RemediationPrioritizer(graph)

    plan = prioritizer.generate_plan(
        source_id="USR-104"
    )

    isolation_candidates = [
        candidate
        for candidate in plan.candidates
        if candidate.action_type
        == RemediationActionType.ISOLATE_NODE
    ]

    assert isolation_candidates

    action_ids = {
        candidate.action_id
        for candidate in isolation_candidates
    }

    assert "ISOLATE-DEV-018" in action_ids


def test_connection_candidates_are_created() -> None:
    graph = build_graph()
    prioritizer = RemediationPrioritizer(graph)

    plan = prioritizer.generate_plan(
        source_id="USR-104"
    )

    connection_candidates = [
        candidate
        for candidate in plan.candidates
        if candidate.action_type
        == RemediationActionType.DISABLE_CONNECTION
    ]

    assert connection_candidates

    assert all(
        candidate.target_node_id is not None
        for candidate in connection_candidates
    )


def test_original_graph_is_not_modified() -> None:
    graph = build_graph()

    before_edge_count = graph.statistics().edge_count

    prioritizer = RemediationPrioritizer(graph)

    prioritizer.generate_plan(
        source_id="USR-104"
    )

    after_edge_count = graph.statistics().edge_count

    assert before_edge_count == after_edge_count

    enabled_targets = {
        relationship.node.node_id
        for relationship in graph.neighbours(
            "DEV-018",
            enabled_only=True,
        )
    }

    assert "EXAM-APP-01" in enabled_targets
    assert "IDP-001" in enabled_targets
    assert "PORTAL-001" in enabled_targets


def test_maximum_recommendation_limit() -> None:
    graph = build_graph()
    prioritizer = RemediationPrioritizer(graph)

    plan = prioritizer.generate_plan(
        source_id="USR-104",
        maximum_recommendations=3,
    )

    assert plan.recommended_action_count <= 3
    assert len(plan.candidates) <= 3


def test_invalid_recommendation_limit_is_rejected() -> None:
    graph = build_graph()
    prioritizer = RemediationPrioritizer(graph)

    with pytest.raises(
        ValueError,
        match=(
            "maximum_recommendations "
            "must be greater than zero"
        ),
    ):
        prioritizer.generate_plan(
            source_id="USR-104",
            maximum_recommendations=0,
        )


def test_unknown_source_is_rejected() -> None:
    graph = build_graph()
    prioritizer = RemediationPrioritizer(graph)

    with pytest.raises(
        KeyError,
        match="Node not found",
    ):
        prioritizer.generate_plan(
            source_id="UNKNOWN-NODE"
        )