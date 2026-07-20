from app.ueba.baseline import BehaviourBaselineService


def test_build_user_profile() -> None:
    events = [
        {
            "user_id": "USR-104",
            "device_id": "DEV-018",
            "source_ip": "10.0.1.18",
            "asset_id": "EXAM-APP-01",
            "event_type": "login_success",
            "attributes": {
                "login_hour": 10,
                "failed_login_count": 0,
                "data_transfer_mb": 10,
            },
        },
        {
            "user_id": "USR-104",
            "device_id": "DEV-018",
            "source_ip": "10.0.1.18",
            "asset_id": "EXAM-APP-01",
            "event_type": "file_read",
            "attributes": {
                "login_hour": 12,
                "failed_login_count": 0,
                "data_transfer_mb": 20,
            },
        },
    ]

    service = BehaviourBaselineService()
    profiles = service.fit(events)

    profile = profiles["USR-104"]

    assert profile.event_count == 2
    assert profile.mean_login_hour == 11
    assert profile.mean_data_transfer_mb == 15
    assert profile.known_devices == ["DEV-018"]


def test_explain_abnormal_login() -> None:
    service = BehaviourBaselineService()

    service.fit(
        [
            {
                "user_id": "USR-104",
                "device_id": "DEV-018",
                "source_ip": "10.0.1.18",
                "asset_id": "EXAM-APP-01",
                "attributes": {
                    "login_hour": 10,
                    "failed_login_count": 0,
                    "data_transfer_mb": 10,
                },
            }
            for _ in range(20)
        ]
    )

    profile = service.get_profile("USR-104")
    assert profile is not None

    reasons = service.explain_deviation(
        {
            "user_id": "USR-104",
            "device_id": "UNKNOWN-DEVICE",
            "source_ip": "203.0.113.25",
            "asset_id": "EXAM-DB-01",
            "attributes": {
                "login_hour": 2,
                "failed_login_count": 7,
                "data_transfer_mb": 700,
                "impossible_travel": True,
            },
        },
        profile,
    )

    codes = {reason.code for reason in reasons}

    assert "OFF_HOURS_LOGIN" in codes
    assert "NEW_DEVICE" in codes
    assert "NEW_SOURCE_IP" in codes
    assert "UNUSUAL_ASSET_ACCESS" in codes
    assert "FAILED_LOGIN_SPIKE" in codes
    assert "DATA_TRANSFER_SPIKE" in codes
    assert "IMPOSSIBLE_TRAVEL" in codes