from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.response.approval import (
    ApprovalEngine,
)
from app.response.schemas import (
    ApprovalDecision,
    ApprovalMode,
    ApprovalStatus,
    ExecutionStatus,
    ResponseActionType,
    ResponseExecution,
    ResponseRiskLevel,
    ResponseStepExecution,
    ResponseTarget,
)


def build_step(
    step_id: str,
    approval_mode: ApprovalMode,
) -> ResponseStepExecution:
    return ResponseStepExecution(
        execution_step_id=step_id,
        step_number=1,
        action_id="ACT-TEST",
        action_type=(
            ResponseActionType.ISOLATE_ENDPOINT
        ),
        status=ExecutionStatus.PROPOSED,
        approval_mode=approval_mode,
        approval_status=ApprovalStatus.PENDING,
        required_approval_count=0,
        risk_level=ResponseRiskLevel.HIGH,
        target_ids=["DEV-018"],
    )


def build_execution(
    execution_id: str,
    steps: list[ResponseStepExecution],
) -> ResponseExecution:
    return ResponseExecution(
        execution_id=execution_id,
        incident_id="INC-001",
        playbook_id="PB-TEST",
        status=ExecutionStatus.PROPOSED,
        requested_by="analyst.requester",
        dry_run=True,
        targets=[
            ResponseTarget(
                target_id="DEV-018",
                target_type="workstation",
            )
        ],
        steps=steps,
    )


def make_decision(
    execution_id: str,
    step_id: str,
    approver_id: str,
    approved: bool = True,
) -> ApprovalDecision:
    return ApprovalDecision(
        execution_id=execution_id,
        execution_step_id=step_id,
        approver_id=approver_id,
        approved=approved,
        reason="Reviewed by SOC analyst",
        decided_at=datetime.now(
            timezone.utc
        ),
    )


def test_automatic_step_needs_no_approval() -> None:
    engine = ApprovalEngine()

    execution = build_execution(
        "EXEC-001",
        [
            build_step(
                "STEP-001",
                ApprovalMode.AUTOMATIC,
            )
        ],
    )

    registered = engine.register_execution(
        execution
    )

    assert registered.status == (
        ExecutionStatus.APPROVED
    )

    step = registered.steps[0]

    assert step.status == (
        ExecutionStatus.APPROVED
    )

    assert step.approval_status == (
        ApprovalStatus.NOT_REQUIRED
    )

    assert step.required_approval_count == 0


def test_human_required_step_waits_for_approval() -> None:
    engine = ApprovalEngine()

    execution = build_execution(
        "EXEC-002",
        [
            build_step(
                "STEP-002",
                ApprovalMode.HUMAN_REQUIRED,
            )
        ],
    )

    registered = engine.register_execution(
        execution
    )

    assert registered.status == (
        ExecutionStatus.PENDING_APPROVAL
    )

    state = engine.require_state(
        "STEP-002"
    )

    assert state.required_approval_count == 1
    assert state.remaining_approval_count == 1
    assert state.can_execute is False


def test_single_approval_authorises_human_step() -> None:
    engine = ApprovalEngine()

    execution = engine.register_execution(
        build_execution(
            "EXEC-003",
            [
                build_step(
                    "STEP-003",
                    ApprovalMode.HUMAN_REQUIRED,
                )
            ],
        )
    )

    state = engine.submit_decision(
        make_decision(
            "EXEC-003",
            "STEP-003",
            "analyst.one",
        )
    )

    assert state.status == (
        ApprovalStatus.APPROVED
    )

    assert state.approval_count == 1
    assert state.remaining_approval_count == 0
    assert state.can_execute is True

    updated = (
        engine.apply_states_to_execution(
            execution
        )
    )

    assert updated.status == (
        ExecutionStatus.APPROVED
    )


def test_dual_approval_needs_two_people() -> None:
    engine = ApprovalEngine()

    execution = engine.register_execution(
        build_execution(
            "EXEC-004",
            [
                build_step(
                    "STEP-004",
                    ApprovalMode
                    .DUAL_APPROVAL_REQUIRED,
                )
            ],
        )
    )

    first = engine.submit_decision(
        make_decision(
            "EXEC-004",
            "STEP-004",
            "analyst.one",
        )
    )

    assert first.status == (
        ApprovalStatus.PENDING
    )

    assert first.approval_count == 1
    assert first.remaining_approval_count == 1
    assert first.can_execute is False

    second = engine.submit_decision(
        make_decision(
            "EXEC-004",
            "STEP-004",
            "analyst.two",
        )
    )

    assert second.status == (
        ApprovalStatus.APPROVED
    )

    assert second.approval_count == 2
    assert second.remaining_approval_count == 0
    assert second.can_execute is True

    updated = (
        engine.apply_states_to_execution(
            execution
        )
    )

    assert updated.status == (
        ExecutionStatus.APPROVED
    )


def test_same_approver_cannot_approve_twice() -> None:
    engine = ApprovalEngine()

    engine.register_execution(
        build_execution(
            "EXEC-005",
            [
                build_step(
                    "STEP-005",
                    ApprovalMode
                    .DUAL_APPROVAL_REQUIRED,
                )
            ],
        )
    )

    engine.submit_decision(
        make_decision(
            "EXEC-005",
            "STEP-005",
            "analyst.one",
        )
    )

    with pytest.raises(
        ValueError,
        match="already decided",
    ):
        engine.submit_decision(
            make_decision(
                "EXEC-005",
                "STEP-005",
                "analyst.one",
            )
        )


def test_rejection_blocks_step() -> None:
    engine = ApprovalEngine()

    execution = engine.register_execution(
        build_execution(
            "EXEC-006",
            [
                build_step(
                    "STEP-006",
                    ApprovalMode.HUMAN_REQUIRED,
                )
            ],
        )
    )

    state = engine.submit_decision(
        make_decision(
            "EXEC-006",
            "STEP-006",
            "analyst.one",
            approved=False,
        )
    )

    assert state.status == (
        ApprovalStatus.REJECTED
    )

    assert state.rejection_count == 1
    assert state.can_execute is False

    updated = (
        engine.apply_states_to_execution(
            execution
        )
    )

    assert updated.status == (
        ExecutionStatus.REJECTED
    )

    assert updated.steps[0].status == (
        ExecutionStatus.REJECTED
    )


def test_rejected_step_cannot_receive_more_decisions() -> None:
    engine = ApprovalEngine()

    engine.register_execution(
        build_execution(
            "EXEC-007",
            [
                build_step(
                    "STEP-007",
                    ApprovalMode
                    .DUAL_APPROVAL_REQUIRED,
                )
            ],
        )
    )

    engine.submit_decision(
        make_decision(
            "EXEC-007",
            "STEP-007",
            "analyst.one",
            approved=False,
        )
    )

    with pytest.raises(
        ValueError,
        match="Rejected steps",
    ):
        engine.submit_decision(
            make_decision(
                "EXEC-007",
                "STEP-007",
                "analyst.two",
                approved=True,
            )
        )


def test_automatic_step_rejects_manual_decision() -> None:
    engine = ApprovalEngine()

    engine.register_execution(
        build_execution(
            "EXEC-008",
            [
                build_step(
                    "STEP-008",
                    ApprovalMode.AUTOMATIC,
                )
            ],
        )
    )

    with pytest.raises(
        ValueError,
        match="Automatic steps",
    ):
        engine.submit_decision(
            make_decision(
                "EXEC-008",
                "STEP-008",
                "analyst.one",
            )
        )


def test_step_must_belong_to_execution() -> None:
    engine = ApprovalEngine()

    engine.register_execution(
        build_execution(
            "EXEC-009",
            [
                build_step(
                    "STEP-009",
                    ApprovalMode.HUMAN_REQUIRED,
                )
            ],
        )
    )

    with pytest.raises(
        KeyError,
        match="does not belong",
    ):
        engine.submit_decision(
            make_decision(
                "EXEC-WRONG",
                "STEP-009",
                "analyst.one",
            )
        )


def test_mixed_execution_waits_for_human_step() -> None:
    engine = ApprovalEngine()

    execution = engine.register_execution(
        build_execution(
            "EXEC-010",
            [
                build_step(
                    "STEP-010-A",
                    ApprovalMode.AUTOMATIC,
                ),
                ResponseStepExecution(
                    execution_step_id=(
                        "STEP-010-B"
                    ),
                    step_number=2,
                    action_id="ACT-TEST-2",
                    action_type=(
                        ResponseActionType
                        .REVOKE_CREDENTIALS
                    ),
                    status=(
                        ExecutionStatus.PROPOSED
                    ),
                    approval_mode=(
                        ApprovalMode.HUMAN_REQUIRED
                    ),
                    approval_status=(
                        ApprovalStatus.PENDING
                    ),
                    required_approval_count=0,
                    risk_level=(
                        ResponseRiskLevel.HIGH
                    ),
                    target_ids=["USR-104"],
                ),
            ],
        )
    )

    assert execution.status == (
        ExecutionStatus.PENDING_APPROVAL
    )

    engine.submit_decision(
        make_decision(
            "EXEC-010",
            "STEP-010-B",
            "analyst.one",
        )
    )

    updated = (
        engine.apply_states_to_execution(
            execution
        )
    )

    assert updated.status == (
        ExecutionStatus.APPROVED
    )

    assert all(
        step.status
        == ExecutionStatus.APPROVED
        for step in updated.steps
    )


def test_execution_rejection_detection() -> None:
    engine = ApprovalEngine()

    engine.register_execution(
        build_execution(
            "EXEC-011",
            [
                build_step(
                    "STEP-011",
                    ApprovalMode.HUMAN_REQUIRED,
                )
            ],
        )
    )

    assert (
        engine.execution_has_rejection(
            "EXEC-011"
        )
        is False
    )

    engine.submit_decision(
        make_decision(
            "EXEC-011",
            "STEP-011",
            "analyst.one",
            approved=False,
        )
    )

    assert (
        engine.execution_has_rejection(
            "EXEC-011"
        )
        is True
    )

    assert (
        engine.execution_is_authorised(
            "EXEC-011"
        )
        is False
    )