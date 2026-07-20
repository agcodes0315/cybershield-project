from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.response.audit import (
    GENESIS_HASH,
    AuditActorType,
    AuditEventType,
    TamperEvidentAuditLedger,
)


def test_first_record_uses_genesis_hash() -> None:
    ledger = TamperEvidentAuditLedger()

    record = ledger.append(
        event_type=(
            AuditEventType.EXECUTION_CREATED
        ),
        execution_id="EXEC-001",
        incident_id="INC-001",
        actor_id="soc.requester",
        actor_type=AuditActorType.USER,
        payload={
            "playbook_id": "PB-TEST",
        },
    )

    assert record.sequence_number == 1
    assert record.previous_hash == GENESIS_HASH
    assert len(record.record_hash) == 64


def test_records_are_hash_chained() -> None:
    ledger = TamperEvidentAuditLedger()

    first = ledger.append(
        event_type=(
            AuditEventType.EXECUTION_CREATED
        ),
        execution_id="EXEC-001",
        actor_id="soc.requester",
        actor_type=AuditActorType.USER,
    )

    second = ledger.append(
        event_type=(
            AuditEventType.APPROVAL_GRANTED
        ),
        execution_id="EXEC-001",
        execution_step_id="STEP-001",
        actor_id="analyst.one",
        actor_type=AuditActorType.USER,
    )

    assert second.sequence_number == 2

    assert (
        second.previous_hash
        == first.record_hash
    )


def test_valid_ledger_passes_verification() -> None:
    ledger = TamperEvidentAuditLedger()

    ledger.append(
        event_type=(
            AuditEventType.EXECUTION_CREATED
        ),
        execution_id="EXEC-001",
        actor_id="system",
        actor_type=AuditActorType.SYSTEM,
    )

    ledger.append(
        event_type=(
            AuditEventType.EXECUTION_STARTED
        ),
        execution_id="EXEC-001",
        actor_id="response-service",
        actor_type=AuditActorType.SERVICE,
    )

    ledger.append(
        event_type=(
            AuditEventType.EXECUTION_COMPLETED
        ),
        execution_id="EXEC-001",
        actor_id="response-service",
        actor_type=AuditActorType.SERVICE,
    )

    result = ledger.verify()

    assert result.valid is True
    assert result.record_count == 3
    assert result.verified_record_count == 3


def test_tampered_payload_fails_verification() -> None:
    ledger = TamperEvidentAuditLedger()

    ledger.append(
        event_type=(
            AuditEventType.EXECUTION_CREATED
        ),
        execution_id="EXEC-001",
        actor_id="system",
        actor_type=AuditActorType.SYSTEM,
        payload={
            "severity": "high",
        },
    )

    # Deliberate test-only mutation.
    ledger._records[0].payload[
        "severity"
    ] = "low"

    result = ledger.verify()

    assert result.valid is False
    assert result.first_invalid_sequence == 1
    assert result.expected_hash is not None
    assert result.actual_hash is not None


def test_tampered_previous_hash_fails() -> None:
    ledger = TamperEvidentAuditLedger()

    ledger.append(
        event_type=(
            AuditEventType.EXECUTION_CREATED
        ),
        execution_id="EXEC-001",
        actor_id="system",
        actor_type=AuditActorType.SYSTEM,
    )

    ledger.append(
        event_type=(
            AuditEventType.EXECUTION_STARTED
        ),
        execution_id="EXEC-001",
        actor_id="response-service",
        actor_type=AuditActorType.SERVICE,
    )

    ledger._records[1].previous_hash = (
        "f" * 64
    )

    result = ledger.verify()

    assert result.valid is False
    assert result.first_invalid_sequence == 2
    assert (
        "previous-hash"
        in result.explanation
    )


def test_execution_index_returns_records() -> None:
    ledger = TamperEvidentAuditLedger()

    ledger.append(
        event_type=(
            AuditEventType.EXECUTION_CREATED
        ),
        execution_id="EXEC-001",
        actor_id="system",
        actor_type=AuditActorType.SYSTEM,
    )

    ledger.append(
        event_type=(
            AuditEventType.EXECUTION_CREATED
        ),
        execution_id="EXEC-002",
        actor_id="system",
        actor_type=AuditActorType.SYSTEM,
    )

    ledger.append(
        event_type=(
            AuditEventType.EXECUTION_COMPLETED
        ),
        execution_id="EXEC-001",
        actor_id="response-service",
        actor_type=AuditActorType.SERVICE,
    )

    records = ledger.records_for_execution(
        "EXEC-001"
    )

    assert len(records) == 2

    assert all(
        record.execution_id == "EXEC-001"
        for record in records
    )


def test_summary_reports_integrity() -> None:
    ledger = TamperEvidentAuditLedger()

    ledger.append(
        event_type=(
            AuditEventType.EXECUTION_CREATED
        ),
        execution_id="EXEC-001",
        actor_id="system",
        actor_type=AuditActorType.SYSTEM,
    )

    ledger.append(
        event_type=(
            AuditEventType.EXECUTION_CREATED
        ),
        execution_id="EXEC-002",
        actor_id="system",
        actor_type=AuditActorType.SYSTEM,
    )

    summary = ledger.summary()

    assert summary.record_count == 2
    assert summary.execution_count == 2
    assert summary.valid is True
    assert len(summary.latest_hash) == 64


def test_export_and_reload_json(
    tmp_path: Path,
) -> None:
    original = TamperEvidentAuditLedger()

    original.append(
        event_type=(
            AuditEventType.EXECUTION_CREATED
        ),
        execution_id="EXEC-001",
        actor_id="system",
        actor_type=AuditActorType.SYSTEM,
        payload={
            "playbook_id": "PB-TEST",
        },
    )

    output_path = (
        tmp_path / "audit-ledger.json"
    )

    original.export_json(output_path)

    loaded = TamperEvidentAuditLedger()

    verification = loaded.load_json(
        output_path
    )

    assert verification.valid is True
    assert len(loaded.records()) == 1

    assert (
        loaded.records()[0].record_hash
        == original.records()[0].record_hash
    )


def test_tampered_export_is_rejected(
    tmp_path: Path,
) -> None:
    original = TamperEvidentAuditLedger()

    original.append(
        event_type=(
            AuditEventType.EXECUTION_CREATED
        ),
        execution_id="EXEC-001",
        actor_id="system",
        actor_type=AuditActorType.SYSTEM,
        payload={
            "severity": "critical",
        },
    )

    output_path = (
        tmp_path / "audit-ledger.json"
    )

    original.export_json(output_path)

    data = json.loads(
        output_path.read_text(
            encoding="utf-8"
        )
    )

    data[0]["payload"]["severity"] = "low"

    output_path.write_text(
        json.dumps(data, indent=2),
        encoding="utf-8",
    )

    loaded = TamperEvidentAuditLedger()

    with pytest.raises(
        ValueError,
        match="integrity verification",
    ):
        loaded.load_json(output_path)


def test_empty_identifiers_are_rejected() -> None:
    ledger = TamperEvidentAuditLedger()

    with pytest.raises(
        ValueError,
        match="execution_id cannot be empty",
    ):
        ledger.append(
            event_type=(
                AuditEventType
                .EXECUTION_CREATED
            ),
            execution_id="",
            actor_id="system",
            actor_type=(
                AuditActorType.SYSTEM
            ),
        )

    with pytest.raises(
        ValueError,
        match="actor_id cannot be empty",
    ):
        ledger.append(
            event_type=(
                AuditEventType
                .EXECUTION_CREATED
            ),
            execution_id="EXEC-001",
            actor_id="",
            actor_type=(
                AuditActorType.SYSTEM
            ),
        )