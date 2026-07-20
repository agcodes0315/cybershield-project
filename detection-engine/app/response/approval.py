from __future__ import annotations

from threading import RLock

from .schemas import (
    ApprovalDecision,
    ApprovalMode,
    ApprovalRecord,
    ApprovalStatus,
    ExecutionStatus,
    ResponseExecution,
    ResponseStepExecution,
    StepApprovalState,
)


class ApprovalEngine:
    """
    Human-approval state machine for SOAR actions.

    Rules:
    - AUTOMATIC requires zero approvals.
    - HUMAN_REQUIRED requires one unique approval.
    - DUAL_APPROVAL_REQUIRED requires two unique approvals.
    - Any rejection permanently rejects the step.
    - One analyst cannot approve the same step twice.

    Data structures:
    - Hash map for O(1)-average step-state lookup.
    - Sets for unique approver enforcement.
    - Lock for thread-safe decision processing.
    """

    def __init__(self) -> None:
        self._states: dict[
            str,
            StepApprovalState,
        ] = {}

        self._execution_index: dict[
            str,
            set[str],
        ] = {}

        self._lock = RLock()

    @staticmethod
    def required_approval_count(
        approval_mode: ApprovalMode,
    ) -> int:
        return {
            ApprovalMode.AUTOMATIC: 0,
            ApprovalMode.HUMAN_REQUIRED: 1,
            ApprovalMode.DUAL_APPROVAL_REQUIRED: 2,
        }[approval_mode]

    def register_step(
        self,
        execution_id: str,
        step: ResponseStepExecution,
    ) -> StepApprovalState:
        with self._lock:
            if (
                step.execution_step_id
                in self._states
            ):
                raise ValueError(
                    "Approval state already exists for step: "
                    f"{step.execution_step_id}"
                )

            required_count = (
                self.required_approval_count(
                    step.approval_mode
                )
            )

            if required_count == 0:
                status = ApprovalStatus.NOT_REQUIRED
                can_execute = True
            else:
                status = ApprovalStatus.PENDING
                can_execute = False

            state = StepApprovalState(
                execution_step_id=(
                    step.execution_step_id
                ),
                approval_mode=step.approval_mode,
                status=status,
                required_approval_count=(
                    required_count
                ),
                approval_count=0,
                rejection_count=0,
                approved_by=[],
                rejected_by=[],
                decisions=[],
                remaining_approval_count=(
                    required_count
                ),
                can_execute=can_execute,
            )

            self._states[
                step.execution_step_id
            ] = state

            self._execution_index.setdefault(
                execution_id,
                set(),
            ).add(
                step.execution_step_id
            )

            return state.model_copy(deep=True)

    def register_execution(
        self,
        execution: ResponseExecution,
    ) -> ResponseExecution:
        with self._lock:
            updated_steps: list[
                ResponseStepExecution
            ] = []

            for step in execution.steps:
                state = self.register_step(
                    execution_id=(
                        execution.execution_id
                    ),
                    step=step,
                )

                if state.can_execute:
                    step_status = (
                        ExecutionStatus.APPROVED
                    )
                else:
                    step_status = (
                        ExecutionStatus
                        .PENDING_APPROVAL
                    )

                updated_steps.append(
                    step.model_copy(
                        update={
                            "status": step_status,
                            "approval_status": (
                                state.status
                            ),
                            "required_approval_count": (
                                state
                                .required_approval_count
                            ),
                            "approved_by": [],
                            "rejected_by": [],
                        }
                    )
                )

            execution_status = (
                self._calculate_execution_status(
                    updated_steps
                )
            )

            return execution.model_copy(
                update={
                    "steps": updated_steps,
                    "status": execution_status,
                }
            )

    def submit_decision(
        self,
        decision: ApprovalDecision,
    ) -> StepApprovalState:
        with self._lock:
            self._validate_execution_membership(
                execution_id=decision.execution_id,
                execution_step_id=(
                    decision.execution_step_id
                ),
            )

            state = self.require_state(
                decision.execution_step_id
            )

            if (
                state.approval_mode
                == ApprovalMode.AUTOMATIC
            ):
                raise ValueError(
                    "Automatic steps do not accept "
                    "approval decisions"
                )

            if state.status == ApprovalStatus.REJECTED:
                raise ValueError(
                    "Rejected steps cannot receive "
                    "additional decisions"
                )

            if state.status == ApprovalStatus.APPROVED:
                raise ValueError(
                    "Approved steps cannot receive "
                    "additional decisions"
                )

            previous_approvers = set(
                state.approved_by
            )
            previous_rejectors = set(
                state.rejected_by
            )

            if (
                decision.approver_id
                in previous_approvers
                or decision.approver_id
                in previous_rejectors
            ):
                raise ValueError(
                    "Approver has already decided on "
                    f"step {decision.execution_step_id}"
                )

            record = ApprovalRecord(
                approver_id=decision.approver_id,
                approved=decision.approved,
                reason=decision.reason,
                decided_at=decision.decided_at,
            )

            decisions = [
                *state.decisions,
                record,
            ]

            if not decision.approved:
                rejected_by = [
                    *state.rejected_by,
                    decision.approver_id,
                ]

                updated = state.model_copy(
                    update={
                        "status": (
                            ApprovalStatus.REJECTED
                        ),
                        "rejection_count": (
                            state.rejection_count + 1
                        ),
                        "rejected_by": rejected_by,
                        "decisions": decisions,
                        "can_execute": False,
                    }
                )

                self._states[
                    decision.execution_step_id
                ] = updated

                return updated.model_copy(
                    deep=True
                )

            approved_by = [
                *state.approved_by,
                decision.approver_id,
            ]

            approval_count = len(
                approved_by
            )

            remaining_count = max(
                state.required_approval_count
                - approval_count,
                0,
            )

            if (
                approval_count
                >= state.required_approval_count
            ):
                status = ApprovalStatus.APPROVED
                can_execute = True
            else:
                status = ApprovalStatus.PENDING
                can_execute = False

            updated = state.model_copy(
                update={
                    "status": status,
                    "approval_count": (
                        approval_count
                    ),
                    "approved_by": approved_by,
                    "decisions": decisions,
                    "remaining_approval_count": (
                        remaining_count
                    ),
                    "can_execute": can_execute,
                }
            )

            self._states[
                decision.execution_step_id
            ] = updated

            return updated.model_copy(deep=True)

    def apply_state_to_step(
        self,
        step: ResponseStepExecution,
    ) -> ResponseStepExecution:
        state = self.require_state(
            step.execution_step_id
        )

        if state.status == ApprovalStatus.REJECTED:
            execution_status = (
                ExecutionStatus.REJECTED
            )
        elif state.can_execute:
            execution_status = (
                ExecutionStatus.APPROVED
            )
        else:
            execution_status = (
                ExecutionStatus.PENDING_APPROVAL
            )

        return step.model_copy(
            update={
                "status": execution_status,
                "approval_status": state.status,
                "required_approval_count": (
                    state.required_approval_count
                ),
                "approved_by": [
                    *state.approved_by
                ],
                "rejected_by": [
                    *state.rejected_by
                ],
            }
        )

    def apply_states_to_execution(
        self,
        execution: ResponseExecution,
    ) -> ResponseExecution:
        updated_steps = [
            self.apply_state_to_step(step)
            for step in execution.steps
        ]

        status = self._calculate_execution_status(
            updated_steps
        )

        return execution.model_copy(
            update={
                "steps": updated_steps,
                "status": status,
            }
        )

    def get_state(
        self,
        execution_step_id: str,
    ) -> StepApprovalState | None:
        with self._lock:
            state = self._states.get(
                execution_step_id
            )

            if state is None:
                return None

            return state.model_copy(deep=True)

    def require_state(
        self,
        execution_step_id: str,
    ) -> StepApprovalState:
        state = self.get_state(
            execution_step_id
        )

        if state is None:
            raise KeyError(
                "Approval state not found for step: "
                f"{execution_step_id}"
            )

        return state

    def states_for_execution(
        self,
        execution_id: str,
    ) -> list[StepApprovalState]:
        with self._lock:
            step_ids = sorted(
                self._execution_index.get(
                    execution_id,
                    set(),
                )
            )

            return [
                self._states[step_id].model_copy(
                    deep=True
                )
                for step_id in step_ids
            ]

    def execution_is_authorised(
        self,
        execution_id: str,
    ) -> bool:
        states = self.states_for_execution(
            execution_id
        )

        if not states:
            return False

        return all(
            state.can_execute
            for state in states
        )

    def execution_has_rejection(
        self,
        execution_id: str,
    ) -> bool:
        return any(
            state.status
            == ApprovalStatus.REJECTED
            for state in self.states_for_execution(
                execution_id
            )
        )

    def clear(self) -> None:
        with self._lock:
            self._states.clear()
            self._execution_index.clear()

    def _validate_execution_membership(
        self,
        execution_id: str,
        execution_step_id: str,
    ) -> None:
        execution_steps = (
            self._execution_index.get(
                execution_id
            )
        )

        if (
            execution_steps is None
            or execution_step_id
            not in execution_steps
        ):
            raise KeyError(
                "Step does not belong to execution: "
                f"{execution_id}/{execution_step_id}"
            )

    @staticmethod
    def _calculate_execution_status(
        steps: list[ResponseStepExecution],
    ) -> ExecutionStatus:
        if any(
            step.status
            == ExecutionStatus.REJECTED
            for step in steps
        ):
            return ExecutionStatus.REJECTED

        if any(
            step.status
            == ExecutionStatus.PENDING_APPROVAL
            for step in steps
        ):
            return ExecutionStatus.PENDING_APPROVAL

        if steps and all(
            step.status
            == ExecutionStatus.APPROVED
            for step in steps
        ):
            return ExecutionStatus.APPROVED

        return ExecutionStatus.PROPOSED


approval_engine = ApprovalEngine()