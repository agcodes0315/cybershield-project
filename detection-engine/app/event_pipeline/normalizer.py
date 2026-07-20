from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict

from .schemas import Actor, SecurityEvent, Severity, SourceType, Target


SEVERITY_ALIASES = {
    "informational": Severity.INFO,
    "info": Severity.INFO,
    "low": Severity.LOW,
    "moderate": Severity.MEDIUM,
    "medium": Severity.MEDIUM,
    "warning": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
    "severe": Severity.CRITICAL,
}


SOURCE_ALIASES = {
    "auth": SourceType.AUTHENTICATION,
    "authentication": SourceType.AUTHENTICATION,
    "endpoint": SourceType.ENDPOINT,
    "edr": SourceType.ENDPOINT,
    "network": SourceType.NETWORK,
    "firewall": SourceType.NETWORK,
    "email": SourceType.EMAIL,
    "url": SourceType.URL_SCANNER,
    "url_scanner": SourceType.URL_SCANNER,
    "vulnerability": SourceType.VULNERABILITY,
    "vulnerability_scanner": SourceType.VULNERABILITY,
    "threat_intel": SourceType.THREAT_INTELLIGENCE,
    "threat_intelligence": SourceType.THREAT_INTELLIGENCE,
    "cloud": SourceType.CLOUD,
    "ot": SourceType.OT,
    "simulator": SourceType.SIMULATOR,
}


def _normalise_timestamp(value: Any) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)

    if isinstance(value, datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    if isinstance(value, str):
        cleaned = value.strip().replace("Z", "+00:00")
        parsed = datetime.fromisoformat(cleaned)

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)

        return parsed.astimezone(timezone.utc)

    raise ValueError("Unsupported timestamp format")


def _normalise_severity(value: Any) -> Severity:
    if isinstance(value, Severity):
        return value

    text = str(value or "info").strip().lower()
    return SEVERITY_ALIASES.get(text, Severity.INFO)


def _normalise_source(value: Any) -> SourceType:
    if isinstance(value, SourceType):
        return value

    text = str(value or "simulator").strip().lower()

    if text not in SOURCE_ALIASES:
        raise ValueError(f"Unsupported source type: {value}")

    return SOURCE_ALIASES[text]


def normalise_event(raw_event: Dict[str, Any]) -> SecurityEvent:
    """
    Convert telemetry from any CyberShield component into one standard event.

    Supported aliases allow the existing URL scanner, email analyser,
    endpoint simulator and network modules to use different input names.
    """
    actor_data = raw_event.get("actor") or {}
    target_data = raw_event.get("target") or {}

    actor = Actor(
        user_id=actor_data.get("user_id") or raw_event.get("user_id"),
        username=actor_data.get("username") or raw_event.get("username"),
        device_id=actor_data.get("device_id") or raw_event.get("device_id"),
        source_ip=actor_data.get("source_ip")
        or raw_event.get("source_ip")
        or raw_event.get("ip"),
        department=actor_data.get("department")
        or raw_event.get("department"),
    )

    target = Target(
        asset_id=target_data.get("asset_id") or raw_event.get("asset_id"),
        asset_name=target_data.get("asset_name")
        or raw_event.get("asset_name"),
        destination_ip=target_data.get("destination_ip")
        or raw_event.get("destination_ip"),
        destination_port=target_data.get("destination_port")
        or raw_event.get("destination_port"),
        resource=target_data.get("resource") or raw_event.get("resource"),
    )

    event_type = (
        raw_event.get("event_type")
        or raw_event.get("type")
        or raw_event.get("action")
    )

    if not event_type:
        raise ValueError("event_type is required")

    known_fields = {
        "event_id",
        "timestamp",
        "source_type",
        "source",
        "event_type",
        "type",
        "action",
        "severity",
        "actor",
        "target",
        "user_id",
        "username",
        "device_id",
        "source_ip",
        "ip",
        "department",
        "asset_id",
        "asset_name",
        "destination_ip",
        "destination_port",
        "resource",
        "anomaly_score",
        "confidence",
        "indicators",
        "tags",
        "organisation_id",
        "raw_event_reference",
    }

    extra_attributes = {
        key: value
        for key, value in raw_event.items()
        if key not in known_fields
    }

    supplied_attributes = raw_event.get("attributes") or {}
    attributes = {**extra_attributes, **supplied_attributes}

    event_payload = {
        "timestamp": _normalise_timestamp(raw_event.get("timestamp")),
        "source_type": _normalise_source(
            raw_event.get("source_type") or raw_event.get("source")
        ),
        "event_type": str(event_type).strip().lower(),
        "severity": _normalise_severity(raw_event.get("severity")),
        "actor": actor,
        "target": target,
        "anomaly_score": float(raw_event.get("anomaly_score", 0.0)),
        "confidence": float(raw_event.get("confidence", 0.0)),
        "attributes": attributes,
        "indicators": raw_event.get("indicators") or [],
        "tags": raw_event.get("tags") or [],
        "organisation_id": raw_event.get(
            "organisation_id",
            "ORG-DEMO-001",
        ),
        "raw_event_reference": raw_event.get("raw_event_reference"),
    }

    if raw_event.get("event_id"):
        event_payload["event_id"] = raw_event["event_id"]

    return SecurityEvent(**event_payload)
