from datetime import datetime, timezone

import pytest

from app.event_pipeline.normalizer import normalise_event
from app.event_pipeline.schemas import Severity, SourceType
from app.event_pipeline.service import EventPipelineService


def test_normalise_authentication_event() -> None:
    event = normalise_event(
        {
            "source": "auth",
            "type": "login_success",
            "severity": "warning",
            "timestamp": "2026-07-17T08:30:00Z",
            "user_id": "USR-104",
            "device_id": "DEV-018",
            "source_ip": "203.0.113.25",
            "asset_id": "IDP-001",
            "new_device": True,
            "login_hour": 2,
            "confidence": 0.84,
        }
    )

    assert event.source_type == SourceType.AUTHENTICATION
    assert event.severity == Severity.MEDIUM
    assert event.event_type == "login_success"
    assert event.actor.user_id == "USR-104"
    assert event.actor.device_id == "DEV-018"
    assert event.target.asset_id == "IDP-001"
    assert event.attributes["new_device"] is True
    assert event.attributes["login_hour"] == 2


def test_event_entity_keys() -> None:
    event = normalise_event(
        {
            "source": "endpoint",
            "event_type": "process_execution",
            "user_id": "USR-104",
            "device_id": "DEV-018",
            "source_ip": "10.0.1.18",
            "asset_id": "EXAM-APP-01",
        }
    )

    assert "user:USR-104" in event.entity_keys()
    assert "device:DEV-018" in event.entity_keys()
    assert "source_ip:10.0.1.18" in event.entity_keys()
    assert "asset:EXAM-APP-01" in event.entity_keys()


def test_hashmap_lookup_and_entity_index() -> None:
    service = EventPipelineService(retention_minutes=120)

    event = normalise_event(
        {
            "event_id": "EVT-TEST-001",
            "timestamp": datetime.now(timezone.utc),
            "source": "network",
            "event_type": "internal_connection",
            "severity": "high",
            "device_id": "DEV-018",
            "asset_id": "EXAM-DB-01",
            "destination_ip": "10.0.5.20",
        }
    )

    service.ingest(event)

    assert service.count() == 1
    assert service.get("EVT-TEST-001") == event

    device_events = service.get_events_for_entity("device:DEV-018")
    assert len(device_events) == 1
    assert device_events[0].event_id == "EVT-TEST-001"


def test_duplicate_event_is_rejected() -> None:
    service = EventPipelineService()

    event = normalise_event(
        {
            "event_id": "EVT-DUPLICATE",
            "source": "email",
            "event_type": "phishing_email_detected",
        }
    )

    service.ingest(event)

    with pytest.raises(ValueError, match="Duplicate event_id"):
        service.ingest(event)


def test_missing_event_type_is_rejected() -> None:
    with pytest.raises(ValueError, match="event_type is required"):
        normalise_event(
            {
                "source": "endpoint",
                "device_id": "DEV-001",
            }
        )
