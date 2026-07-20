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


def load_scenario_events() -> list[dict]:
    with SCENARIO_PATH.open("r", encoding="utf-8") as file:
        return json.load(file)


def test_correlation_health_endpoint() -> None:
    response = client.get("/api/correlation/health")

    assert response.status_code == 200

    payload = response.json()

    assert payload["status"] == "healthy"
    assert payload["window_minutes"] == 120
    assert payload["minimum_events"] == 3


def test_correlation_analyse_endpoint() -> None:
    events = load_scenario_events()

    response = client.post(
        "/api/correlation/analyse",
        json={"events": events},
    )

    assert response.status_code == 200

    payload = response.json()

    assert payload["summary"]["events_processed"] == len(events)
    assert payload["summary"]["incidents_created"] >= 1
    assert payload["incidents"]

    incident = max(
        payload["incidents"],
        key=lambda item: item["risk_score"],
    )

    assert incident["primary_entity_id"] == "USR-104"
    assert incident["event_count"] >= 8
    assert incident["stage_count"] >= 6
    assert incident["severity"] in {"high", "critical"}

    assert "MULTI_STAGE_ATTACK" in incident["correlation_rules"]
    assert "DATA_EXFILTRATION_CHAIN" in incident["correlation_rules"]
    assert "EXAM-DB-01" in incident["critical_assets_at_risk"]


def test_mitre_mapping_endpoint() -> None:
    malicious_events = [
        event
        for event in load_scenario_events()
        if event.get("label") == "malicious"
    ]

    response = client.post(
        "/api/correlation/mitre-map",
        json={"events": malicious_events},
    )

    assert response.status_code == 200

    mappings = response.json()

    assert len(mappings) == 8
    assert all(mapping["matched"] for mapping in mappings)

    technique_ids = {
        technique["technique_id"]
        for mapping in mappings
        for technique in mapping["techniques"]
    }

    assert "T1566.002" in technique_ids
    assert "T1059.001" in technique_ids
    assert "T1003" in technique_ids
    assert "T1021" in technique_ids
    assert "T1041" in technique_ids


def test_incident_lookup_endpoint() -> None:
    events = load_scenario_events()

    analysis_response = client.post(
        "/api/correlation/analyse",
        json={"events": events},
    )

    assert analysis_response.status_code == 200

    incident_id = analysis_response.json()["incidents"][0]["incident_id"]

    response = client.get(
        f"/api/correlation/incidents/{incident_id}"
    )

    assert response.status_code == 200
    assert response.json()["incident_id"] == incident_id


def test_unknown_incident_returns_404() -> None:
    response = client.get(
        "/api/correlation/incidents/INC-DOES-NOT-EXIST"
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "Incident not found"