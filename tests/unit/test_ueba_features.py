from app.ueba.feature_extractor import extract_features
from app.ueba.schemas import BehaviourProfile


def test_extract_normal_event_features() -> None:
    event = {
        "user_id": "USR-104",
        "device_id": "DEV-018",
        "source_ip": "10.0.1.18",
        "asset_id": "EXAM-APP-01",
        "attributes": {
            "login_hour": 11,
            "new_device": False,
            "failed_login_count": 0,
            "data_transfer_mb": 10,
        },
    }

    profile = BehaviourProfile(
        entity_id="USR-104",
        known_devices=["DEV-018"],
        known_assets=["EXAM-APP-01"],
        known_source_ips=["10.0.1.18"],
    )

    vector = extract_features(event, profile)

    assert vector.is_off_hours == 0.0
    assert vector.new_device == 0.0
    assert vector.external_source_ip == 0.0
    assert vector.first_time_asset_access == 0.0


def test_extract_malicious_features() -> None:
    event = {
        "user_id": "USR-104",
        "device_id": "UNKNOWN-DEVICE",
        "source_ip": "203.0.113.25",
        "asset_id": "EXAM-DB-01",
        "attributes": {
            "login_hour": 2,
            "new_device": True,
            "new_location": True,
            "failed_login_count": 8,
            "encoded_command": True,
            "privilege_escalation_observed": True,
            "data_transfer_mb": 742.8,
            "process_name": "powershell.exe",
        },
    }

    profile = BehaviourProfile(
        entity_id="USR-104",
        known_devices=["DEV-018"],
        known_assets=["EXAM-APP-01"],
        known_source_ips=["10.0.1.18"],
        known_processes=["chrome.exe"],
    )

    vector = extract_features(event, profile)

    assert vector.is_off_hours == 1.0
    assert vector.new_device == 1.0
    assert vector.new_location == 1.0
    assert vector.encoded_command == 1.0
    assert vector.privileged_action == 1.0
    assert vector.sensitive_asset_access == 1.0
    assert vector.first_time_asset_access == 1.0