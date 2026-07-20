import json
from pathlib import Path

from app.correlation.schemas import IncidentSeverity
from app.correlation.service import CorrelationService


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATASET_PATH = (
    PROJECT_ROOT
    / "event-simulator"
    / "datasets"
    / "silent_intruder_events.json"
)


def load_scenario_events():
    with DATASET_PATH.open(
        "r",
        encoding="utf-8",
    ) as file:
        return json.load(file)


def test_correlates_silent_intruder() -> None:
    events = load_scenario_events()

    service = CorrelationService(
        window_minutes=120,
        minimum_events=3,
    )

    incidents, summary = service.correlate(events)

    assert summary.incidents_created >= 1

    incident = max(
        incidents,
        key=lambda item: item.risk_score,
    )

    assert incident.primary_entity_id == "USR-104"
    assert incident.event_count >= 8
    assert incident.stage_count >= 6
    assert incident.severity in {
        IncidentSeverity.HIGH,
        IncidentSeverity.CRITICAL,
    }

    assert "EXAM-DB-01" in (
        incident.critical_assets_at_risk
    )

    assert "MULTI_STAGE_ATTACK" in (
        incident.correlation_rules
    )

    assert "DATA_EXFILTRATION_CHAIN" in (
        incident.correlation_rules
    )


def test_normal_activity_does_not_create_incident() -> None:
    events = [
        {
            "event_id": f"NORMAL-{index}",
            "timestamp": (
                f"2026-07-17T10:{index:02d}:00+00:00"
            ),
            "event_type": "file_read",
            "source_type": "endpoint",
            "user_id": "USR-200",
            "device_id": "DEV-200",
            "asset_id": "PORTAL-001",
            "anomaly_score": 0.10,
            "label": "normal",
        }
        for index in range(10)
    ]

    service = CorrelationService()

    incidents, summary = service.correlate(events)

    assert incidents == []
    assert summary.incidents_created == 0