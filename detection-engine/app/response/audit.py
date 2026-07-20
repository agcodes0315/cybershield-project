from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from threading import RLock
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


GENESIS_HASH = "0" * 64


class AuditEventType(str, Enum):
    EXECUTION_CREATED = "execution_created"
    APPROVAL_GRANTED = "approval_granted"
    APPROVAL_REJECTED = "approval_rejected"
    EXECUTION_STARTED = "execution_started"
    STEP_STARTED = "step_started"
    STEP_COMPLETED = "step_completed"
    STEP_FAILED = "step_failed"
    EXECUTION_COMPLETED = "execution_completed"
    EXECUTION_FAILED = "execution_failed"
    EXECUTION_REJECTED = "execution_rejected"
    EXECUTION_CANCELLED = "execution_cancelled"
    ROLLBACK_COMPLETED = "rollback_completed"


class AuditActorType(str, Enum):
    USER = "user"
    SYSTEM = "system"
    SERVICE = "service"


class AuditRecord(BaseModel):
    sequence_number: int = Field(ge=1)

    record_id: str
    event_type: AuditEventType

    execution_id: str
    incident_id: str | None = None
    execution_step_id: str | None = None

    actor_id: str
    actor_type: AuditActorType

    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(
            timezone.utc
        )
    )

    payload: dict[str, Any] = Field(
        default_factory=dict
    )

    previous_hash: str = Field(
        min_length=64,
        max_length=64,
    )

    record_hash: str = Field(
        min_length=64,
        max_length=64,
    )


class AuditVerificationResult(BaseModel):
    valid: bool

    record_count: int = Field(ge=0)
    verified_record_count: int = Field(ge=0)

    first_invalid_sequence: int | None = None
    first_invalid_record_id: str | None = None

    expected_hash: str | None = None
    actual_hash: str | None = None

    explanation: str


class AuditLedgerSummary(BaseModel):
    record_count: int = Field(ge=0)
    execution_count: int = Field(ge=0)

    first_recorded_at: datetime | None = None
    last_recorded_at: datetime | None = None

    latest_hash: str

    valid: bool


class TamperEvidentAuditLedger:
    """
    Append-only SHA-256 chained audit ledger.

    Each record hash depends on:
    - sequence number
    - event type
    - execution and incident identifiers
    - actor
    - timestamp
    - canonical payload
    - previous record hash

    Modifying, deleting, inserting or reordering records causes
    verification to fail.
    """

    def __init__(self) -> None:
        self._records: list[AuditRecord] = []
        self._execution_index: dict[
            str,
            list[int],
        ] = {}

        self._lock = RLock()

    def append(
        self,
        event_type: AuditEventType,
        execution_id: str,
        actor_id: str,
        actor_type: AuditActorType,
        payload: dict[str, Any] | None = None,
        incident_id: str | None = None,
        execution_step_id: str | None = None,
        timestamp: datetime | None = None,
    ) -> AuditRecord:
        if not execution_id.strip():
            raise ValueError(
                "execution_id cannot be empty"
            )

        if not actor_id.strip():
            raise ValueError(
                "actor_id cannot be empty"
            )

        with self._lock:
            sequence_number = (
                len(self._records) + 1
            )

            previous_hash = (
                self._records[-1].record_hash
                if self._records
                else GENESIS_HASH
            )

            record_id = (
                f"AUD-{uuid4().hex[:16].upper()}"
            )

            recorded_at = (
                timestamp
                or datetime.now(timezone.utc)
            )

            safe_payload = self._normalise_payload(
                payload or {}
            )

            hash_payload = self._hash_payload(
                sequence_number=sequence_number,
                record_id=record_id,
                event_type=event_type,
                execution_id=execution_id,
                incident_id=incident_id,
                execution_step_id=(
                    execution_step_id
                ),
                actor_id=actor_id,
                actor_type=actor_type,
                timestamp=recorded_at,
                payload=safe_payload,
                previous_hash=previous_hash,
            )

            record_hash = self._calculate_hash(
                hash_payload
            )

            record = AuditRecord(
                sequence_number=sequence_number,
                record_id=record_id,
                event_type=event_type,
                execution_id=execution_id,
                incident_id=incident_id,
                execution_step_id=(
                    execution_step_id
                ),
                actor_id=actor_id,
                actor_type=actor_type,
                timestamp=recorded_at,
                payload=safe_payload,
                previous_hash=previous_hash,
                record_hash=record_hash,
            )

            self._records.append(record)

            self._execution_index.setdefault(
                execution_id,
                [],
            ).append(
                sequence_number - 1
            )

            return record.model_copy(deep=True)

    def records(
        self,
    ) -> list[AuditRecord]:
        with self._lock:
            return [
                record.model_copy(deep=True)
                for record in self._records
            ]

    def records_for_execution(
        self,
        execution_id: str,
    ) -> list[AuditRecord]:
        with self._lock:
            indexes = self._execution_index.get(
                execution_id,
                [],
            )

            return [
                self._records[index].model_copy(
                    deep=True
                )
                for index in indexes
            ]

    def latest_record(
        self,
    ) -> AuditRecord | None:
        with self._lock:
            if not self._records:
                return None

            return self._records[-1].model_copy(
                deep=True
            )

    def verify(
        self,
    ) -> AuditVerificationResult:
        with self._lock:
            previous_hash = GENESIS_HASH

            for index, record in enumerate(
                self._records,
                start=1,
            ):
                if record.sequence_number != index:
                    return AuditVerificationResult(
                        valid=False,
                        record_count=len(
                            self._records
                        ),
                        verified_record_count=(
                            index - 1
                        ),
                        first_invalid_sequence=index,
                        first_invalid_record_id=(
                            record.record_id
                        ),
                        expected_hash=None,
                        actual_hash=(
                            record.record_hash
                        ),
                        explanation=(
                            "Audit sequence numbering "
                            "is invalid."
                        ),
                    )

                if (
                    record.previous_hash
                    != previous_hash
                ):
                    return AuditVerificationResult(
                        valid=False,
                        record_count=len(
                            self._records
                        ),
                        verified_record_count=(
                            index - 1
                        ),
                        first_invalid_sequence=index,
                        first_invalid_record_id=(
                            record.record_id
                        ),
                        expected_hash=previous_hash,
                        actual_hash=(
                            record.previous_hash
                        ),
                        explanation=(
                            "The previous-hash link "
                            "does not match."
                        ),
                    )

                expected_hash = (
                    self._calculate_hash(
                        self._hash_payload(
                            sequence_number=(
                                record
                                .sequence_number
                            ),
                            record_id=(
                                record.record_id
                            ),
                            event_type=(
                                record.event_type
                            ),
                            execution_id=(
                                record.execution_id
                            ),
                            incident_id=(
                                record.incident_id
                            ),
                            execution_step_id=(
                                record
                                .execution_step_id
                            ),
                            actor_id=(
                                record.actor_id
                            ),
                            actor_type=(
                                record.actor_type
                            ),
                            timestamp=(
                                record.timestamp
                            ),
                            payload=(
                                record.payload
                            ),
                            previous_hash=(
                                record.previous_hash
                            ),
                        )
                    )
                )

                if (
                    record.record_hash
                    != expected_hash
                ):
                    return AuditVerificationResult(
                        valid=False,
                        record_count=len(
                            self._records
                        ),
                        verified_record_count=(
                            index - 1
                        ),
                        first_invalid_sequence=index,
                        first_invalid_record_id=(
                            record.record_id
                        ),
                        expected_hash=(
                            expected_hash
                        ),
                        actual_hash=(
                            record.record_hash
                        ),
                        explanation=(
                            "The record hash does not "
                            "match its stored contents."
                        ),
                    )

                previous_hash = (
                    record.record_hash
                )

            return AuditVerificationResult(
                valid=True,
                record_count=len(self._records),
                verified_record_count=len(
                    self._records
                ),
                explanation=(
                    "Every audit record and hash-chain "
                    "link is valid."
                ),
            )

    def summary(
        self,
    ) -> AuditLedgerSummary:
        with self._lock:
            verification = self.verify()

            execution_ids = {
                record.execution_id
                for record in self._records
            }

            return AuditLedgerSummary(
                record_count=len(self._records),
                execution_count=len(
                    execution_ids
                ),
                first_recorded_at=(
                    self._records[0].timestamp
                    if self._records
                    else None
                ),
                last_recorded_at=(
                    self._records[-1].timestamp
                    if self._records
                    else None
                ),
                latest_hash=(
                    self._records[-1].record_hash
                    if self._records
                    else GENESIS_HASH
                ),
                valid=verification.valid,
            )

    def export_json(
        self,
        output_path: Path,
    ) -> Path:
        with self._lock:
            output_path.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            data = [
                record.model_dump(
                    mode="json"
                )
                for record in self._records
            ]

            output_path.write_text(
                json.dumps(
                    data,
                    indent=2,
                    sort_keys=True,
                ),
                encoding="utf-8",
            )

            return output_path

    def load_json(
        self,
        input_path: Path,
        verify_after_load: bool = True,
    ) -> AuditVerificationResult:
        if not input_path.exists():
            raise FileNotFoundError(
                f"Audit ledger not found: {input_path}"
            )

        raw_data = json.loads(
            input_path.read_text(
                encoding="utf-8"
            )
        )

        if not isinstance(raw_data, list):
            raise ValueError(
                "Audit ledger JSON must contain a list"
            )

        loaded_records = [
            AuditRecord.model_validate(item)
            for item in raw_data
        ]

        with self._lock:
            self._records = loaded_records
            self._rebuild_execution_index()

            result = self.verify()

            if (
                verify_after_load
                and not result.valid
            ):
                self.clear()

                raise ValueError(
                    "Loaded audit ledger failed "
                    "integrity verification: "
                    f"{result.explanation}"
                )

            return result

    def clear(self) -> None:
        with self._lock:
            self._records.clear()
            self._execution_index.clear()

    def _rebuild_execution_index(
        self,
    ) -> None:
        self._execution_index.clear()

        for index, record in enumerate(
            self._records
        ):
            self._execution_index.setdefault(
                record.execution_id,
                [],
            ).append(index)

    @staticmethod
    def _normalise_payload(
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        serialised = json.dumps(
            payload,
            default=str,
            sort_keys=True,
        )

        return json.loads(serialised)

    @staticmethod
    def _hash_payload(
        sequence_number: int,
        record_id: str,
        event_type: AuditEventType,
        execution_id: str,
        incident_id: str | None,
        execution_step_id: str | None,
        actor_id: str,
        actor_type: AuditActorType,
        timestamp: datetime,
        payload: dict[str, Any],
        previous_hash: str,
    ) -> dict[str, Any]:
        return {
            "sequence_number": sequence_number,
            "record_id": record_id,
            "event_type": event_type.value,
            "execution_id": execution_id,
            "incident_id": incident_id,
            "execution_step_id": (
                execution_step_id
            ),
            "actor_id": actor_id,
            "actor_type": actor_type.value,
            "timestamp": timestamp.isoformat(),
            "payload": payload,
            "previous_hash": previous_hash,
        }

    @staticmethod
    def _calculate_hash(
        payload: dict[str, Any],
    ) -> str:
        canonical_json = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )

        return hashlib.sha256(
            canonical_json.encode("utf-8")
        ).hexdigest()


audit_ledger = TamperEvidentAuditLedger()