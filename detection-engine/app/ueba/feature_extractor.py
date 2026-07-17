from __future__ import annotations

import ipaddress
import math
from datetime import datetime
from typing import Any, Mapping

from .schemas import BehaviourFeatureVector, BehaviourProfile


CRITICAL_ASSETS = {
    "IDP-001",
    "EXAM-APP-01",
    "EXAM-DB-01",
    "QUESTION-REPO-01",
}

COMMON_PROCESSES = {
    "chrome.exe",
    "msedge.exe",
    "explorer.exe",
    "outlook.exe",
    "teams.exe",
    "python.exe",
}


def _attributes(event: Mapping[str, Any]) -> Mapping[str, Any]:
    value = event.get("attributes")
    return value if isinstance(value, Mapping) else {}


def _timestamp_hour(event: Mapping[str, Any]) -> float:
    attributes = _attributes(event)

    if attributes.get("login_hour") is not None:
        try:
            return float(attributes["login_hour"])
        except (TypeError, ValueError):
            pass

    timestamp = event.get("timestamp")

    if isinstance(timestamp, datetime):
        return float(timestamp.hour)

    if isinstance(timestamp, str):
        cleaned = timestamp.replace("Z", "+00:00")

        try:
            return float(datetime.fromisoformat(cleaned).hour)
        except ValueError:
            return 12.0

    return 12.0


def _is_external_ip(value: Any) -> float:
    if not value:
        return 0.0

    try:
        address = ipaddress.ip_address(str(value))
        return 0.0 if address.is_private else 1.0
    except ValueError:
        return 1.0


def _boolean(value: Any) -> float:
    return 1.0 if bool(value) else 0.0


def _numeric(value: Any, default: float = 0.0) -> float:
    try:
        number = float(value)
        return number if math.isfinite(number) else default
    except (TypeError, ValueError):
        return default


def extract_features(
    event: Mapping[str, Any],
    profile: BehaviourProfile | None = None,
) -> BehaviourFeatureVector:
    attributes = _attributes(event)

    login_hour = _timestamp_hour(event)
    process_name = str(
        attributes.get("process_name") or ""
    ).strip().lower()

    device_id = str(event.get("device_id") or "")
    source_ip = str(event.get("source_ip") or "")
    asset_id = str(event.get("asset_id") or "")

    new_device = bool(attributes.get("new_device"))
    first_time_asset = bool(
        attributes.get("previously_contacted_asset") is False
        or attributes.get("first_time_connection")
    )

    rare_process = bool(
        process_name
        and process_name not in COMMON_PROCESSES
    )

    if profile is not None:
        if device_id and device_id not in profile.known_devices:
            new_device = True

        if asset_id and asset_id not in profile.known_assets:
            first_time_asset = True

        if (
            process_name
            and profile.known_processes
            and process_name not in profile.known_processes
        ):
            rare_process = True

    transfer_mb = _numeric(
        attributes.get(
            "data_transfer_mb",
            attributes.get("transfer_mb", 0.0),
        )
    )

    # Log scaling prevents one huge transfer from dominating every feature.
    scaled_transfer = math.log1p(max(transfer_mb, 0.0))

    return BehaviourFeatureVector(
        login_hour=login_hour / 23.0,
        is_off_hours=_boolean(login_hour < 7 or login_hour > 21),
        new_device=_boolean(new_device),
        new_location=_boolean(attributes.get("new_location")),
        failed_login_count=min(
            _numeric(attributes.get("failed_login_count")) / 10.0,
            1.0,
        ),
        encoded_command=_boolean(attributes.get("encoded_command")),
        privileged_action=_boolean(
            attributes.get("privileged_action")
            or attributes.get("privilege_escalation_observed")
        ),
        data_transfer_mb=min(scaled_transfer / 8.0, 1.0),
        rare_process=_boolean(rare_process),
        sensitive_asset_access=_boolean(asset_id in CRITICAL_ASSETS),
        external_source_ip=_is_external_ip(source_ip),
        first_time_asset_access=_boolean(first_time_asset),
    )