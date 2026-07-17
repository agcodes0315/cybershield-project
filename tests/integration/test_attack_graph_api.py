from __future__ import annotations

from fastapi.testclient import TestClient

from app.attack_graph.service import attack_graph_service
from app.main import app


client = TestClient(app)


def setup_function() -> None:
    attack_graph_service.reset()


def test_attack_graph_health() -> None:
    response = client.get(
        "/api/attack-graph/health"
    )

    assert response.status_code == 200

    payload = response.json()

    assert payload["status"] == "healthy"
    assert payload["module"] == "attack-graph"
    assert "breadth-first search" in payload["algorithms"]


def test_load_default_topology() -> None:
    response = client.post(
        "/api/attack-graph/topology/load-default"
    )

    assert response.status_code == 200

    payload = response.json()

    assert payload["topology_id"] == (
        "TOPO-CNI-EXAM-001"
    )

    assert len(payload["nodes"]) == 9
    assert len(payload["edges"]) == 13


def test_graph_statistics() -> None:
    response = client.get(
        "/api/attack-graph/statistics"
    )

    assert response.status_code == 200

    payload = response.json()

    assert payload["node_count"] == 9
    assert payload["edge_count"] == 13
    assert payload["critical_node_count"] == 5
    assert payload["compromised_node_count"] == 2


def test_bfs_path_endpoint() -> None:
    response = client.post(
        "/api/attack-graph/path/bfs",
        json={
            "source_id": "USR-104",
            "target_id": "EXAM-DB-01",
        },
    )

    assert response.status_code == 200

    payload = response.json()

    assert payload["found"] is True
    assert payload["algorithm"] == "bfs"

    assert payload["node_ids"] == [
        "USR-104",
        "DEV-018",
        "EXAM-APP-01",
        "EXAM-DB-01",
    ]

    assert payload["hop_count"] == 3


def test_dijkstra_path_endpoint() -> None:
    response = client.post(
        "/api/attack-graph/path/dijkstra",
        json={
            "source_id": "USR-104",
            "target_id": "EXAM-DB-01",
        },
    )

    assert response.status_code == 200

    payload = response.json()

    assert payload["found"] is True
    assert payload["algorithm"] == "dijkstra"
    assert payload["total_cost"] > 0
    assert payload["path_risk_score"] > 0


def test_blast_radius_endpoint() -> None:
    response = client.post(
        "/api/attack-graph/blast-radius",
        json={
            "source_id": "USR-104",
            "include_source": True,
        },
    )

    assert response.status_code == 200

    payload = response.json()

    assert payload["reachable_node_count"] >= 8
    assert payload["critical_node_count"] >= 4

    assert "EXAM-DB-01" in (
        payload["critical_assets_at_risk"]
    )


def test_containment_comparison_endpoint() -> None:
    response = client.post(
        "/api/attack-graph/containment/compare",
        json={
            "source_id": "USR-104",
            "connections": [
                {
                    "source_id": "DEV-018",
                    "target_id": "EXAM-APP-01",
                },
                {
                    "source_id": "DEV-018",
                    "target_id": "IDP-001",
                },
                {
                    "source_id": "DEV-018",
                    "target_id": "PORTAL-001",
                },
            ],
        },
    )

    assert response.status_code == 200

    payload = response.json()

    assert (
        payload["before"]["reachable_node_count"]
        > payload["after"]["reachable_node_count"]
    )

    assert payload["removed_reachable_nodes"] > 0
    assert payload["blast_radius_reduction"] > 0


def test_remediation_plan_endpoint() -> None:
    response = client.post(
        "/api/attack-graph/remediation/plan",
        json={
            "source_id": "USR-104",
            "maximum_recommendations": 5,
        },
    )

    assert response.status_code == 200

    payload = response.json()

    assert payload["candidate_count"] > 0
    assert payload["recommended_action_count"] > 0
    assert payload["recommended_action_count"] <= 5
    assert payload["top_recommendation"] is not None

    scores = [
        candidate["priority_score"]
        for candidate in payload["candidates"]
    ]

    assert scores == sorted(
        scores,
        reverse=True,
    )


def test_unknown_node_returns_404() -> None:
    response = client.post(
        "/api/attack-graph/path/bfs",
        json={
            "source_id": "UNKNOWN-NODE",
            "target_id": "EXAM-DB-01",
        },
    )

    assert response.status_code == 404