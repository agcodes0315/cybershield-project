"""
CyberShield tamper-evident audit trail.

Each audit record contains:

- the hash of the previous record;
- a SHA-256 hash of its own canonical contents;
- a timestamp;
- the actor, action, target and supporting details.

Any modification to an existing record breaks verification of the chain.

Current prototype storage:
    In-memory storage for safe hackathon demonstration.

Production upgrade:
    Persist records in PostgreSQL and restrict mutation permissions.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from threading import Lock
from typing import Any
from uuid import uuid4

from fastapi import APIRouter, Query
from pydantic import BaseModel, Field, field_validator

router = APIRouter()


GENESIS_HASH = "0" * 64

_AUDIT_CHAIN: list[dict[str, Any]] = []
_AUDIT_LOCK = Lock()


class AuditEntryIn(BaseModel):
    incident_id: str | None = Field(
        default=None,
        max_length=100,
    )

    actor: str = Field(
        min_length=1,
        max_length=200,
    )

    action: str = Field(
        min_length=1,
        max_length=200,
    )

    target: str | None = Field(
        default=None,
        max_length=2000,
    )

    details: dict[str, Any] = Field(default_factory=dict)

    @field_validator("actor", "action")
    @classmethod
    def clean_required_strings(cls, value: str) -> str:
        cleaned = value.strip()

        if not cleaned:
            raise ValueError("Value must not be empty.")

        return cleaned

    @field_validator("incident_id", "target")
    @classmethod
    def clean_optional_strings(
        cls,
        value: str | None,
    ) -> str | None:
        if value is None:
            return None

        cleaned = value.strip()

        return cleaned or None


def _canonical_json(value: dict[str, Any]) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )


def _calculate_hash(
    previous_hash: str,
    record_without_hash: dict[str, Any],
) -> str:
    canonical_record = _canonical_json(record_without_hash)

    payload = (
        previous_hash
        + canonical_record
    ).encode("utf-8")

    return hashlib.sha256(payload).hexdigest()


def append_entry(entry_input: AuditEntryIn) -> dict[str, Any]:
    with _AUDIT_LOCK:
        previous_hash = (
            _AUDIT_CHAIN[-1]["entry_hash"]
            if _AUDIT_CHAIN
            else GENESIS_HASH
        )

        base_record: dict[str, Any] = {
            "entry_id": str(uuid4()),
            "sequence_number": len(_AUDIT_CHAIN) + 1,
            "incident_id": entry_input.incident_id,
            "actor": entry_input.actor,
            "action": entry_input.action,
            "target": entry_input.target,
            "details": entry_input.details,
            "previous_hash": previous_hash,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        entry_hash = _calculate_hash(
            previous_hash,
            base_record,
        )

        stored_record = {
            **base_record,
            "entry_hash": entry_hash,
        }

        _AUDIT_CHAIN.append(stored_record)

        return dict(stored_record)


def verify_chain() -> dict[str, Any]:
    with _AUDIT_LOCK:
        expected_previous_hash = GENESIS_HASH

        for index, stored_record in enumerate(_AUDIT_CHAIN):
            record_without_entry_hash = {
                key: value
                for key, value in stored_record.items()
                if key != "entry_hash"
            }

            if (
                stored_record.get("previous_hash")
                != expected_previous_hash
            ):
                return {
                    "valid": False,
                    "entries_checked": index,
                    "broken_at_sequence": stored_record.get(
                        "sequence_number"
                    ),
                    "reason": "Previous hash does not match.",
                }

            recomputed_hash = _calculate_hash(
                expected_previous_hash,
                record_without_entry_hash,
            )

            if recomputed_hash != stored_record.get("entry_hash"):
                return {
                    "valid": False,
                    "entries_checked": index,
                    "broken_at_sequence": stored_record.get(
                        "sequence_number"
                    ),
                    "reason": "Entry hash does not match its contents.",
                }

            expected_previous_hash = stored_record["entry_hash"]

        return {
            "valid": True,
            "entries_checked": len(_AUDIT_CHAIN),
            "latest_hash": (
                _AUDIT_CHAIN[-1]["entry_hash"]
                if _AUDIT_CHAIN
                else GENESIS_HASH
            ),
            "storage_mode": "IN_MEMORY_DEMO",
        }


@router.get("/health")
def audit_health() -> dict:
    return {
        "service": "audit-integrity",
        "status": "healthy",
        "storage_mode": "IN_MEMORY_DEMO",
        "entries": len(_AUDIT_CHAIN),
    }


@router.post("/log")
def log_action(entry_input: AuditEntryIn) -> dict:
    return append_entry(entry_input)


@router.get("/trail")
def get_audit_trail(
    incident_id: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
) -> dict:
    with _AUDIT_LOCK:
        records = list(_AUDIT_CHAIN)

    if incident_id:
        records = [
            record
            for record in records
            if record.get("incident_id") == incident_id
        ]

    records = records[-limit:]

    return {
        "total_returned": len(records),
        "incident_id": incident_id,
        "storage_mode": "IN_MEMORY_DEMO",
        "entries": records,
    }


@router.get("/verify")
def verify_audit_integrity() -> dict:
    return verify_chain()