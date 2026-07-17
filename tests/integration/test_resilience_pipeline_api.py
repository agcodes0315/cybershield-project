from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app
from app.response import (
    response_orchestration_service,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]

EVENT_PATH = (
    PROJECT_ROOT
    / "event-simulator"
    / "datasets"
    / "silent_intruder_events.json"
)

client = TestClient(app)


def setup_function() -> None:
    response_orchestration_service.reset()


def load_malicious_events() -> list[dict]:
    events = json.loads(
        EVENT_PATH.read_text(
            encoding="utf-8"
        )
    )

    return [
        event
        for event in events
        if event.get("label") == "malicious"
    ]


def test_pipeline_health() -> None:
    response = client.get(
        "/api/resilience/health"
    )

    assert response.status_code == 200
    assert response.json()[
        "simulation_only"
    ] is True


def test_pipeline_creates_response_execution() -> None:
    events = load_malicious_events()

    response = client.post(
        "/api/resilience/analyse",
        json={
            "incident_id": (
                "INC-PIPELINE-001"
            ),
            "events": events[:4],
            "source_node_id": "DEV-018",
            "requested_by": (
                "cybershield-pipeline"
            ),
            "prediction_horizon": 3,
            "maximum_recommendations": 5,
            "auto_create_response": True,
        },
    )

    assert response.status_code == 200

    payload = response.json()

    assert payload["prediction"][
        "current_tactic"
    ] == "Credential Access"

    assert payload["prediction"][
        "most_likely_next_tactic"
    ] == "Discovery"

    assert payload[
        "response_execution"
    ] is not None

    assert payload["decision"][
        "simulation_only"
    ] is True

    assert payload["pipeline_steps"]


def test_pipeline_returns_graph_intelligence() -> None:
    events = load_malicious_events()

    response = client.post(
        "/api/resilience/analyse",
        json={
            "incident_id": (
                "INC-PIPELINE-002"
            ),
            "events": events[:6],
            "source_node_id": "DEV-018",
            "auto_create_response": False,
        },
    )

    assert response.status_code == 200

    payload = response.json()

    assert payload[
        "blast_radius"
    ] is not None

    assert payload[
        "remediation_candidates"
    ]

    assert payload[
        "response_execution"
    ] is None


def test_pipeline_audit_record_is_created() -> None:
    events = load_malicious_events()

    response = client.post(
        "/api/resilience/analyse",
        json={
            "incident_id": (
                "INC-PIPELINE-003"
            ),
            "events": events[:7],
            "source_node_id": (
                "EXAM-APP-01"
            ),
            "auto_create_response": True,
        },
    )

    assert response.status_code == 200

    execution = response.json()[
        "response_execution"
    ]

    assert execution is not None

    execution_id = execution[
        "execution_id"
    ]

    audit_response = client.get(
        "/api/response/audit/executions/"
        f"{execution_id}"
    )

    assert audit_response.status_code == 200

    records = audit_response.json()

    assert records
    assert records[0][
        "event_type"
    ] == "execution_created"