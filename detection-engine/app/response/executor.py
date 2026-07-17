from __future__ import annotations

from datetime import datetime, timezone
from threading import RLock
from typing import Any

from .approval import ApprovalEngine
from .schemas import (
    ApprovalStatus,
    ExecutionStatus,
    ResponseActionType,
    ResponseExecution,
    ResponseStepExecution,
)


class SafeResponseExecutor:
    """
    Safe SOAR response executor.

    This executor does not change real infrastructure. It simulates
    approved response actions and returns auditable action results.

    Rules:
    - Unapproved actions cannot execute.
    - Rejected actions can never execute.
    - Automatic actions can execute without human approval.
    - Human-gated actions execute only after required approvals.
    - Dry-run mode is always enforced in this portfolio prototype.
    """

    def __init__(
        self,
        approval_engine: ApprovalEngine,
    ) -> None:
        self.approval_engine = approval_engine
        self._lock = RLock()

    def execute(
        self,
        execution: ResponseExecution,
    ) -> ResponseExecution:
        with self._lock:
            refreshed = (
                self.approval_engine
                .apply_states_to_execution(
                    execution
                )
            )

            if refreshed.status == ExecutionStatus.REJECTED:
                return refreshed.model_copy(
                    update={
                        "summary": (
                            "Execution blocked because one or more "
                            "response steps were rejected."
                        )
                    }
                )

            updated_steps: list[
                ResponseStepExecution
            ] = []

            execution_started_at = datetime.now(
                timezone.utc
            )

            execution_failed = False
            execution_waiting = False

            for step in refreshed.steps:
                if execution_failed:
                    updated_steps.append(step)
                    continue

                if step.status == ExecutionStatus.REJECTED:
                    updated_steps.append(step)
                    execution_failed = True
                    continue

                if step.status == ExecutionStatus.PENDING_APPROVAL:
                    updated_steps.append(step)
                    execution_waiting = True
                    continue

                try:
                    executed_step = self.execute_step(
                        step=step,
                        dry_run=refreshed.dry_run,
                    )

                    updated_steps.append(
                        executed_step
                    )

                    if (
                        executed_step.status
                        == ExecutionStatus.FAILED
                    ):
                        execution_failed = True

                except Exception as exc:
                    failed_step = step.model_copy(
                        update={
                            "status": ExecutionStatus.FAILED,
                            "started_at": datetime.now(
                                timezone.utc
                            ),
                            "completed_at": datetime.now(
                                timezone.utc
                            ),
                            "error_message": str(exc),
                            "result": {
                                "executed": False,
                                "dry_run": refreshed.dry_run,
                            },
                        }
                    )

                    updated_steps.append(failed_step)
                    execution_failed = True

            completed_steps = [
                step
                for step in updated_steps
                if step.status
                == ExecutionStatus.COMPLETED
            ]

            failed_steps = [
                step
                for step in updated_steps
                if step.status
                == ExecutionStatus.FAILED
            ]

            rejected_steps = [
                step
                for step in updated_steps
                if step.status
                == ExecutionStatus.REJECTED
            ]

            pending_steps = [
                step
                for step in updated_steps
                if step.status
                == ExecutionStatus.PENDING_APPROVAL
            ]

            if rejected_steps:
                final_status = ExecutionStatus.REJECTED
            elif failed_steps:
                final_status = ExecutionStatus.FAILED
            elif pending_steps or execution_waiting:
                final_status = (
                    ExecutionStatus.PENDING_APPROVAL
                )
            elif (
                updated_steps
                and len(completed_steps)
                == len(updated_steps)
            ):
                final_status = ExecutionStatus.COMPLETED
            else:
                final_status = ExecutionStatus.PROPOSED

            execution_completed_at = (
                datetime.now(timezone.utc)
                if final_status
                in {
                    ExecutionStatus.COMPLETED,
                    ExecutionStatus.FAILED,
                    ExecutionStatus.REJECTED,
                }
                else None
            )

            summary = (
                f"Completed {len(completed_steps)} steps, "
                f"failed {len(failed_steps)}, "
                f"rejected {len(rejected_steps)}, "
                f"pending approval {len(pending_steps)}."
            )

            return refreshed.model_copy(
                update={
                    "status": final_status,
                    "started_at": (
                        refreshed.started_at
                        or execution_started_at
                    ),
                    "completed_at": (
                        execution_completed_at
                    ),
                    "steps": updated_steps,
                    "summary": summary,
                }
            )

    def execute_step(
        self,
        step: ResponseStepExecution,
        dry_run: bool,
    ) -> ResponseStepExecution:
        state = self.approval_engine.require_state(
            step.execution_step_id
        )

        if state.status == ApprovalStatus.REJECTED:
            raise PermissionError(
                "Rejected response step cannot execute"
            )

        if not state.can_execute:
            raise PermissionError(
                "Response step has not received "
                "the required approval"
            )

        started_at = datetime.now(
            timezone.utc
        )

        executing_step = step.model_copy(
            update={
                "status": ExecutionStatus.EXECUTING,
                "started_at": started_at,
                "error_message": None,
            }
        )

        result = self._simulate_action(
            step=executing_step,
            dry_run=dry_run,
        )

        completed_at = datetime.now(
            timezone.utc
        )

        return executing_step.model_copy(
            update={
                "status": ExecutionStatus.COMPLETED,
                "completed_at": completed_at,
                "result": result,
                "error_message": None,
            }
        )

    def _simulate_action(
        self,
        step: ResponseStepExecution,
        dry_run: bool,
    ) -> dict[str, Any]:
        handlers = {
            ResponseActionType.ISOLATE_ENDPOINT: (
                self._simulate_isolate_endpoint
            ),
            ResponseActionType.REVOKE_CREDENTIALS: (
                self._simulate_revoke_credentials
            ),
            ResponseActionType.BLOCK_IP: (
                self._simulate_block_ip
            ),
            ResponseActionType.DISABLE_CONNECTION: (
                self._simulate_disable_connection
            ),
            ResponseActionType.TERMINATE_SESSION: (
                self._simulate_terminate_session
            ),
            ResponseActionType.SNAPSHOT_ASSET: (
                self._simulate_snapshot_asset
            ),
            ResponseActionType.ENABLE_ENHANCED_MONITORING: (
                self._simulate_enhanced_monitoring
            ),
            ResponseActionType.RESTRICT_DATABASE_ACCESS: (
                self._simulate_restrict_database
            ),
            ResponseActionType.PROTECT_BACKUP: (
                self._simulate_protect_backup
            ),
            ResponseActionType.NOTIFY_SOC: (
                self._simulate_notify_soc
            ),
        }

        handler = handlers.get(
            step.action_type
        )

        if handler is None:
            raise ValueError(
                "Unsupported response action: "
                f"{step.action_type.value}"
            )

        result = handler(step)

        return {
            "executed": True,
            "simulation_only": True,
            "dry_run": dry_run,
            "action_type": step.action_type.value,
            "target_ids": step.target_ids,
            "timestamp": datetime.now(
                timezone.utc
            ).isoformat(),
            **result,
        }

    @staticmethod
    def _simulate_isolate_endpoint(
        step: ResponseStepExecution,
    ) -> dict[str, Any]:
        return {
            "message": (
                "Endpoint isolation simulated successfully."
            ),
            "network_access": "restricted",
            "soc_connectivity": "preserved",
        }

    @staticmethod
    def _simulate_revoke_credentials(
        step: ResponseStepExecution,
    ) -> dict[str, Any]:
        return {
            "message": (
                "Credential revocation simulated successfully."
            ),
            "sessions_revoked": True,
            "credential_rotation_required": True,
        }

    @staticmethod
    def _simulate_block_ip(
        step: ResponseStepExecution,
    ) -> dict[str, Any]:
        return {
            "message": (
                "Temporary IP block simulated successfully."
            ),
            "block_status": "active",
            "ttl_minutes": 60,
        }

    @staticmethod
    def _simulate_disable_connection(
        step: ResponseStepExecution,
    ) -> dict[str, Any]:
        return {
            "message": (
                "Infrastructure connection disablement simulated."
            ),
            "connection_status": "disabled",
        }

    @staticmethod
    def _simulate_terminate_session(
        step: ResponseStepExecution,
    ) -> dict[str, Any]:
        return {
            "message": (
                "Suspicious session termination simulated."
            ),
            "session_status": "terminated",
        }

    @staticmethod
    def _simulate_snapshot_asset(
        step: ResponseStepExecution,
    ) -> dict[str, Any]:
        return {
            "message": (
                "Forensic asset snapshot simulated successfully."
            ),
            "snapshot_created": True,
            "evidence_preserved": True,
        }

    @staticmethod
    def _simulate_enhanced_monitoring(
        step: ResponseStepExecution,
    ) -> dict[str, Any]:
        return {
            "message": (
                "Enhanced monitoring simulated successfully."
            ),
            "monitoring_level": "enhanced",
        }

    @staticmethod
    def _simulate_restrict_database(
        step: ResponseStepExecution,
    ) -> dict[str, Any]:
        return {
            "message": (
                "Database access restriction simulated."
            ),
            "access_policy": "temporary_least_privilege",
        }

    @staticmethod
    def _simulate_protect_backup(
        step: ResponseStepExecution,
    ) -> dict[str, Any]:
        return {
            "message": (
                "Backup protection simulated successfully."
            ),
            "backup_state": "protected",
            "write_restrictions_enabled": True,
        }

    @staticmethod
    def _simulate_notify_soc(
        step: ResponseStepExecution,
    ) -> dict[str, Any]:
        return {
            "message": (
                "SOC notification simulated successfully."
            ),
            "notification_created": True,
            "priority": "high",
        }