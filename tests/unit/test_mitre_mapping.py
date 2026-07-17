from app.mitre.service import MitreMappingService


def test_map_encoded_powershell() -> None:
    service = MitreMappingService()

    result = service.map_event(
        {
            "event_id": "EVT-001",
            "event_type": "process_execution",
            "attributes": {
                "process_name": "powershell.exe",
                "encoded_command": True,
            },
        }
    )

    assert result.matched is True
    assert result.techniques[0].technique_id == "T1059.001"
    assert result.techniques[0].tactic.value == "Execution"
    assert result.confidence >= 0.65


def test_map_credential_dumping() -> None:
    service = MitreMappingService()

    result = service.map_event(
        {
            "event_id": "EVT-002",
            "event_type": "credential_dumping",
            "attributes": {
                "target_process": "lsass.exe",
                "memory_access": True,
            },
        }
    )

    assert result.matched is True
    assert result.techniques[0].technique_id == "T1003"
    assert "LSASS process targeted" in result.evidence


def test_unknown_event_has_no_mapping() -> None:
    service = MitreMappingService()

    result = service.map_event(
        {
            "event_id": "EVT-003",
            "event_type": "ordinary_file_read",
        }
    )

    assert result.matched is False
    assert result.techniques == []