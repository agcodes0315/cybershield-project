from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app


PROJECT_ROOT = Path(__file__).resolve().parents[2]

SCENARIO_PATH = (
    PROJECT_ROOT
    / "event-simulator"
    / "datasets"
    / "silent_intruder_events.json"
)

client = TestClient(app)


def load_malicious_events() -> list[dict]:
    with SCENARIO_PATH.open(
        "r",
        encoding="utf-8",
    ) as file:
        events = json.load(file)

    return [
        event
        for event in events
        if event.get("label") == "malicious"
    ]


def test_prediction_health() -> None:
    response = client.get(
        "/api/prediction/health"
    )

    assert response.status_code == 200

    payload = response.json()

    assert payload["status"] == "healthy"
    assert payload["algorithm"] == (
        "Viterbi dynamic programming"
    )


def test_transition_matrix_endpoint() -> None:
    response = client.get(
        "/api/prediction/transitions"
    )

    assert response.status_code == 200

    payload = response.json()

    assert payload["tactic_count"] > 0
    assert payload["transition_count"] > 0


def test_next_stage_endpoint() -> None:
    events = load_malicious_events()

    response = client.post(
        "/api/prediction/next-stage",
        json={
            "events": events[:4],
            "horizon": 3,
            "source_node_id": "DEV-018",
        },
    )

    assert response.status_code == 200

    payload = response.json()

    assert payload["current_tactic"] == (
        "Credential Access"
    )

    assert payload[
        "most_likely_next_tactic"
    ] == "Discovery"

    assert len(payload["predicted_stages"]) == 3


def test_evaluation_endpoint() -> None:
    events = load_malicious_events()

    response = client.post(
        "/api/prediction/evaluate",
        json={"events": events},
    )

    assert response.status_code == 200

    payload = response.json()

    assert payload["evaluated_prefixes"] >= 6
    assert 0.0 <= payload["top_one_accuracy"] <= 1.0


def test_empty_prediction_request_is_rejected() -> None:
    response = client.post(
        "/api/prediction/next-stage",
        json={
            "events": [],
            "horizon": 3,
        },
    )

    assert response.status_code == 422