from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.response import (
    ApprovalDecision,
    AuditLedgerSummary,
    AuditRecord,
    AuditVerificationResult,
    PlaybookRegistrySummary,
    ResponseActionDefinition,
    ResponseExecution,
    ResponseExecutionRequest,
    ResponsePlaybook,
    StepApprovalState,
    approval_engine,
    audit_ledger,
    playbook_registry,
    response_orchestration_service,
)


router = APIRouter(
    prefix="/api/response",
    tags=["Human-Gated SOAR"],
)


class ApprovalRequest(BaseModel):
    execution_step_id: str = Field(
        min_length=1
    )

    approver_id: str = Field(
        min_length=1
    )

    approved: bool

    reason: str | None = None


@router.get("/health")
def health() -> dict[str, Any]:
    return {
        "status": "healthy",
        "module": "human-gated-soar",
        "simulation_only": True,
        "capabilities": [
            "playbook recommendation",
            "single analyst approval",
            "dual analyst approval",
            "safe simulated execution",
            "SHA-256 audit chaining",
        ],
    }


@router.get(
    "/registry/summary",
    response_model=PlaybookRegistrySummary,
)
def registry_summary() -> (
    PlaybookRegistrySummary
):
    return playbook_registry.summary()


@router.get(
    "/actions",
    response_model=list[
        ResponseActionDefinition
    ],
)
def list_actions() -> list[
    ResponseActionDefinition
]:
    return playbook_registry.actions(
        enabled_only=True
    )


@router.get(
    "/playbooks",
    response_model=list[
        ResponsePlaybook
    ],
)
def list_playbooks() -> list[
    ResponsePlaybook
]:
    return playbook_registry.playbooks(
        enabled_only=True
    )


@router.get(
    "/playbooks/{playbook_id}",
    response_model=ResponsePlaybook,
)
def get_playbook(
    playbook_id: str,
) -> ResponsePlaybook:
    try:
        return playbook_registry.require_playbook(
            playbook_id
        )
    except KeyError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        ) from exc


@router.get(
    "/recommendations",
    response_model=list[
        ResponsePlaybook
    ],
)
def recommend_playbooks(
    tactic: str,
    severity: str,
) -> list[ResponsePlaybook]:
    return playbook_registry.recommend_playbooks(
        tactic=tactic,
        severity=severity,
    )


@router.post(
    "/executions",
    response_model=ResponseExecution,
    status_code=201,
)
def create_execution(
    request: ResponseExecutionRequest,
) -> ResponseExecution:
    try:
        return (
            response_orchestration_service
            .create_execution(request)
        )
    except KeyError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        ) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc


@router.get(
    "/executions",
    response_model=list[
        ResponseExecution
    ],
)
def list_executions() -> list[
    ResponseExecution
]:
    return (
        response_orchestration_service
        .executions()
    )


@router.get(
    "/executions/{execution_id}",
    response_model=ResponseExecution,
)
def get_execution(
    execution_id: str,
) -> ResponseExecution:
    try:
        return (
            response_orchestration_service
            .require_execution(execution_id)
        )
    except KeyError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        ) from exc


@router.get(
    "/executions/{execution_id}/approvals",
    response_model=list[
        StepApprovalState
    ],
)
def execution_approvals(
    execution_id: str,
) -> list[StepApprovalState]:
    try:
        response_orchestration_service.require_execution(
            execution_id
        )

        return (
            approval_engine
            .states_for_execution(execution_id)
        )
    except KeyError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        ) from exc


@router.post(
    "/executions/{execution_id}/approve",
    response_model=ResponseExecution,
)
def submit_approval(
    execution_id: str,
    request: ApprovalRequest,
) -> ResponseExecution:
    try:
        return (
            response_orchestration_service
            .submit_approval(
                ApprovalDecision(
                    execution_id=execution_id,
                    execution_step_id=(
                        request
                        .execution_step_id
                    ),
                    approver_id=(
                        request.approver_id
                    ),
                    approved=request.approved,
                    reason=request.reason,
                )
            )
        )
    except KeyError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        ) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=409,
            detail=str(exc),
        ) from exc


@router.post(
    "/executions/{execution_id}/execute",
    response_model=ResponseExecution,
)
def execute_response(
    execution_id: str,
) -> ResponseExecution:
    try:
        return (
            response_orchestration_service
            .execute(execution_id)
        )
    except KeyError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        ) from exc


@router.get(
    "/audit",
    response_model=list[AuditRecord],
)
def audit_records() -> list[AuditRecord]:
    return audit_ledger.records()


@router.get(
    "/audit/summary",
    response_model=AuditLedgerSummary,
)
def audit_summary() -> (
    AuditLedgerSummary
):
    return audit_ledger.summary()


@router.get(
    "/audit/verify",
    response_model=AuditVerificationResult,
)
def verify_audit() -> (
    AuditVerificationResult
):
    return audit_ledger.verify()


@router.get(
    "/audit/executions/{execution_id}",
    response_model=list[AuditRecord],
)
def execution_audit(
    execution_id: str,
) -> list[AuditRecord]:
    return audit_ledger.records_for_execution(
        execution_id
    )