"""
CyberShield simulated incident response orchestrator.

The orchestrator converts a high-confidence security detection into a
pre-approved response playbook.

Low-blast-radius steps can be executed automatically in simulation mode.
Medium, high and critical steps require human approval.

No live infrastructure is modified.
"""

from __future__ import annotations

from datetime import datetime, timezone
from threading import Lock
from typing import Literal
from uuid import uuid4

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field, field_validator

from app.api.audit_log import AuditEntryIn, append_entry

router = APIRouter()


DetectionSource = Literal[
    "url_scanner",
    "email_analyzer",
    "yara_scanner",
    "recon",
    "breach_check",
]

BlastRadius = Literal[
    "LOW",
    "MEDIUM",
    "HIGH",
    "CRITICAL",
]

DecisionValue = Literal[
    "approve",
    "reject",
]


BLAST_RADIUS_ORDER = {
    "LOW": 0,
    "MEDIUM": 1,
    "HIGH": 2,
    "CRITICAL": 3,
}

APPROVAL_THRESHOLD = "MEDIUM"

_INCIDENTS: dict[str, dict] = {}
_INCIDENT_LOCK = Lock()


ACTION_PLAYBOOKS: dict[str, list[dict[str, str]]] = {
    "url_scanner": [
        {
            "action": "BLOCK_URL_DOMAIN",
            "blast_radius": "LOW",
            "description": (
                "Add the malicious domain to the simulated deny list."
            ),
        },
        {
            "action": "NOTIFY_SOC_ANALYST",
            "blast_radius": "LOW",
            "description": (
                "Generate a simulated SOC analyst notification."
            ),
        },
    ],
    "email_analyzer": [
        {
            "action": "QUARANTINE_EMAIL",
            "blast_radius": "LOW",
            "description": (
                "Move the suspicious message into simulated quarantine."
            ),
        },
        {
            "action": "BLOCK_SENDER_DOMAIN",
            "blast_radius": "MEDIUM",
            "description": (
                "Block the sender domain after human approval."
            ),
        },
        {
            "action": "NOTIFY_SOC_ANALYST",
            "blast_radius": "LOW",
            "description": (
                "Generate a simulated SOC analyst notification."
            ),
        },
    ],
    "yara_scanner": [
        {
            "action": "ISOLATE_SUSPICIOUS_FILE",
            "blast_radius": "LOW",
            "description": (
                "Move the matched file to simulated quarantine."
            ),
        },
        {
            "action": "START_FORENSIC_REVIEW",
            "blast_radius": "MEDIUM",
            "description": (
                "Open a simulated forensic investigation workflow."
            ),
        },
        {
            "action": "NOTIFY_SOC_ANALYST",
            "blast_radius": "LOW",
            "description": (
                "Generate a simulated SOC analyst notification."
            ),
        },
    ],
    "recon": [
        {
            "action": "BLOCK_SOURCE_IP",
            "blast_radius": "MEDIUM",
            "description": (
                "Add the source IP to a simulated firewall deny list."
            ),
        },
        {
            "action": "REVOKE_ACTIVE_SESSIONS",
            "blast_radius": "HIGH",
            "description": (
                "Invalidate simulated sessions associated with the target."
            ),
        },
        {
            "action": "NOTIFY_INCIDENT_COMMANDER",
            "blast_radius": "LOW",
            "description": (
                "Generate a simulated incident commander notification."
            ),
        },
    ],
    "breach_check": [
        {
            "action": "FORCE_PASSWORD_RESET",
            "blast_radius": "MEDIUM",
            "description": (
                "Request a simulated password reset for the affected user."
            ),
        },
        {
            "action": "REVOKE_ACTIVE_SESSIONS",
            "blast_radius": "HIGH",
            "description": (
                "Invalidate simulated active sessions."
            ),
        },
        {
            "action": "NOTIFY_AFFECTED_USER",
            "blast_radius": "LOW",
            "description": (
                "Generate a simulated security notification."
            ),
        },
    ],
}


class DetectionInput(BaseModel):
    source: DetectionSource

    target: str = Field(
        min_length=1,
        max_length=2000,
    )

    confidence: float = Field(
        ge=0,
        le=1,
    )

    reason: str = Field(
        min_length=1,
        max_length=3000,
    )

    severity: Literal[
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    ] = "HIGH"

    @field_validator("target", "reason")
    @classmethod
    def clean_strings(cls, value: str) -> str:
        cleaned = value.strip()

        if not cleaned:
            raise ValueError("Value must not be empty.")

        return cleaned


class ApprovalDecision(BaseModel):
    approver: str = Field(
        min_length=1,
        max_length=200,
    )

    decision: DecisionValue

    action_index: int = Field(
        ge=0,
    )

    note: str | None = Field(
        default=None,
        max_length=2000,
    )

    @field_validator("approver")
    @classmethod
    def clean_approver(cls, value: str) -> str:
        cleaned = value.strip()

        if not cleaned:
            raise ValueError("Approver must not be empty.")

        return cleaned


def requires_human_approval(
    blast_radius: str,
) -> bool:
    return (
        BLAST_RADIUS_ORDER[blast_radius]
        >= BLAST_RADIUS_ORDER[APPROVAL_THRESHOLD]
    )


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def build_actions(
    source: DetectionSource,
) -> list[dict]:
    playbook = ACTION_PLAYBOOKS[source]
    actions: list[dict] = []

    for index, playbook_step in enumerate(playbook):
        blast_radius = playbook_step["blast_radius"]
        approval_required = requires_human_approval(
            blast_radius
        )

        actions.append(
            {
                "action_index": index,
                "action": playbook_step["action"],
                "description": playbook_step["description"],
                "blast_radius": blast_radius,
                "requires_approval": approval_required,
                "status": (
                    "PENDING_APPROVAL"
                    if approval_required
                    else "READY_FOR_AUTO_EXECUTION"
                ),
                "approved_by": None,
                "decision_note": None,
                "executed_at": None,
            }
        )

    return actions


def calculate_incident_status(
    actions: list[dict],
) -> str:
    statuses = {
        action["status"]
        for action in actions
    }

    if statuses and statuses <= {
        "SIMULATED_SUCCESS",
        "REJECTED",
    }:
        return "COMPLETED"

    if "PENDING_APPROVAL" in statuses:
        return "AWAITING_HUMAN_APPROVAL"

    if "READY_FOR_AUTO_EXECUTION" in statuses:
        return "READY_FOR_RESPONSE"

    return "IN_PROGRESS"


def get_incident_or_404(
    incident_id: str,
) -> dict:
    incident = _INCIDENTS.get(incident_id)

    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Incident not found.",
        )

    return incident


@router.get("/health")
def orchestrator_health() -> dict:
    return {
        "service": "response-orchestrator",
        "status": "healthy",
        "execution_mode": "SIMULATED",
        "incidents": len(_INCIDENTS),
    }


@router.post(
    "/incidents",
    status_code=status.HTTP_201_CREATED,
)
def create_incident(
    detection: DetectionInput,
) -> dict:
    incident_id = (
        f"INC-{datetime.now(timezone.utc).year}-"
        f"{uuid4().hex[:8].upper()}"
    )

    incident = {
        "incident_id": incident_id,
        "execution_mode": "SIMULATED",
        "warning": (
            "No live network, endpoint, identity or cloud resource "
            "will be modified."
        ),
        "status": "NEW",
        "detection": detection.model_dump(),
        "actions": build_actions(detection.source),
        "mitre_mapping_status": "PLANNED_NOT_IMPLEMENTED",
        "created_at": utc_now(),
        "updated_at": utc_now(),
    }

    incident["status"] = calculate_incident_status(
        incident["actions"]
    )

    with _INCIDENT_LOCK:
        _INCIDENTS[incident_id] = incident

    append_entry(
        AuditEntryIn(
            incident_id=incident_id,
            actor="response-orchestrator",
            action="INCIDENT_CREATED",
            target=detection.target,
            details={
                "source": detection.source,
                "confidence": detection.confidence,
                "severity": detection.severity,
                "reason": detection.reason,
                "execution_mode": "SIMULATED",
            },
        )
    )

    return incident


@router.get("/incidents")
def list_incidents() -> dict:
    with _INCIDENT_LOCK:
        incidents = list(_INCIDENTS.values())

    incidents.sort(
        key=lambda incident: incident["created_at"],
        reverse=True,
    )

    return {
        "total": len(incidents),
        "execution_mode": "SIMULATED",
        "incidents": incidents,
    }


@router.get("/incidents/{incident_id}")
def get_incident(
    incident_id: str,
) -> dict:
    with _INCIDENT_LOCK:
        incident = get_incident_or_404(incident_id)

        return dict(incident)


@router.post("/incidents/{incident_id}/auto-execute")
def auto_execute_low_risk_actions(
    incident_id: str,
) -> dict:
    executed_actions: list[str] = []

    with _INCIDENT_LOCK:
        incident = get_incident_or_404(incident_id)

        for action in incident["actions"]:
            if (
                action["requires_approval"] is False
                and action["status"]
                == "READY_FOR_AUTO_EXECUTION"
            ):
                action["status"] = "SIMULATED_SUCCESS"
                action["executed_at"] = utc_now()
                executed_actions.append(action["action"])

        incident["updated_at"] = utc_now()
        incident["status"] = calculate_incident_status(
            incident["actions"]
        )

    for action_name in executed_actions:
        append_entry(
            AuditEntryIn(
                incident_id=incident_id,
                actor="response-orchestrator",
                action=f"AUTO_EXECUTE_{action_name}",
                target=incident["detection"]["target"],
                details={
                    "execution_mode": "SIMULATED",
                    "result": "SIMULATED_SUCCESS",
                },
            )
        )

    return {
        "incident": incident,
        "executed_actions": executed_actions,
        "message": (
            "Low-risk actions executed in simulation mode."
            if executed_actions
            else "No eligible low-risk actions remained."
        ),
    }


@router.post("/incidents/{incident_id}/decide")
def decide_action(
    incident_id: str,
    decision: ApprovalDecision,
) -> dict:
    with _INCIDENT_LOCK:
        incident = get_incident_or_404(incident_id)

        if decision.action_index >= len(incident["actions"]):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid action index.",
            )

        action = incident["actions"][
            decision.action_index
        ]

        if action["requires_approval"] is False:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "This low-risk action does not require human "
                    "approval. Use the auto-execute endpoint."
                ),
            )

        if action["status"] != "PENDING_APPROVAL":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    "This action has already received a decision."
                ),
            )

        if decision.decision == "approve":
            action["status"] = "SIMULATED_SUCCESS"
            action["executed_at"] = utc_now()
        else:
            action["status"] = "REJECTED"

        action["approved_by"] = decision.approver
        action["decision_note"] = decision.note

        incident["updated_at"] = utc_now()
        incident["status"] = calculate_incident_status(
            incident["actions"]
        )

    append_entry(
        AuditEntryIn(
            incident_id=incident_id,
            actor=f"human:{decision.approver}",
            action=(
                f"{decision.decision.upper()}_"
                f"{action['action']}"
            ),
            target=incident["detection"]["target"],
            details={
                "action_index": decision.action_index,
                "blast_radius": action["blast_radius"],
                "decision_note": decision.note,
                "execution_mode": "SIMULATED",
                "result": action["status"],
            },
        )
    )

    return {
        "incident": incident,
        "decision": {
            "action": action["action"],
            "decision": decision.decision,
            "result": action["status"],
        },
    }