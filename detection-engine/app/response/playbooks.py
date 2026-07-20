from __future__ import annotations

from threading import RLock

from .schemas import (
    ApprovalMode,
    PlaybookCategory,
    PlaybookRegistrySummary,
    ResponseActionDefinition,
    ResponseActionType,
    ResponsePlaybook,
    ResponsePlaybookStep,
    ResponseRiskLevel,
)


def build_default_actions() -> list[
    ResponseActionDefinition
]:
    return [
        ResponseActionDefinition(
            action_id="ACT-ISOLATE-ENDPOINT",
            name="Isolate Endpoint",
            action_type=(
                ResponseActionType.ISOLATE_ENDPOINT
            ),
            category=PlaybookCategory.ENDPOINT,
            description=(
                "Remove the endpoint from normal network "
                "communication while retaining SOC connectivity."
            ),
            default_approval_mode=(
                ApprovalMode.HUMAN_REQUIRED
            ),
            risk_level=ResponseRiskLevel.HIGH,
            reversible=True,
            estimated_execution_seconds=20,
            required_parameters=[
                "device_id",
            ],
            expected_effects=[
                "Stops lateral movement from the endpoint",
                "Preserves limited forensic connectivity",
            ],
            metadata={
                "safe_simulation_supported": True,
            },
        ),
        ResponseActionDefinition(
            action_id="ACT-REVOKE-CREDENTIALS",
            name="Revoke Credentials",
            action_type=(
                ResponseActionType.REVOKE_CREDENTIALS
            ),
            category=PlaybookCategory.IDENTITY,
            description=(
                "Revoke active sessions and force credential "
                "rotation for the affected identity."
            ),
            default_approval_mode=(
                ApprovalMode.HUMAN_REQUIRED
            ),
            risk_level=ResponseRiskLevel.HIGH,
            reversible=False,
            estimated_execution_seconds=15,
            required_parameters=[
                "user_id",
            ],
            expected_effects=[
                "Terminates active authenticated sessions",
                "Prevents continued use of exposed credentials",
            ],
            metadata={
                "safe_simulation_supported": True,
            },
        ),
        ResponseActionDefinition(
            action_id="ACT-BLOCK-IP",
            name="Block Malicious IP",
            action_type=ResponseActionType.BLOCK_IP,
            category=PlaybookCategory.NETWORK,
            description=(
                "Add a temporary network block for a confirmed "
                "malicious source or destination IP."
            ),
            default_approval_mode=(
                ApprovalMode.AUTOMATIC
            ),
            risk_level=ResponseRiskLevel.MEDIUM,
            reversible=True,
            estimated_execution_seconds=5,
            required_parameters=[
                "ip_address",
            ],
            expected_effects=[
                "Prevents communication with the blocked IP",
            ],
            metadata={
                "safe_simulation_supported": True,
                "default_ttl_minutes": 60,
            },
        ),
        ResponseActionDefinition(
            action_id="ACT-DISABLE-CONNECTION",
            name="Disable Infrastructure Connection",
            action_type=(
                ResponseActionType.DISABLE_CONNECTION
            ),
            category=PlaybookCategory.NETWORK,
            description=(
                "Disable an attack-graph connection between "
                "two infrastructure assets."
            ),
            default_approval_mode=(
                ApprovalMode.HUMAN_REQUIRED
            ),
            risk_level=ResponseRiskLevel.HIGH,
            reversible=True,
            estimated_execution_seconds=10,
            required_parameters=[
                "source_id",
                "target_id",
            ],
            expected_effects=[
                "Breaks a calculated attack path",
                "Reduces the reachable blast radius",
            ],
            metadata={
                "safe_simulation_supported": True,
            },
        ),
        ResponseActionDefinition(
            action_id="ACT-TERMINATE-SESSION",
            name="Terminate Suspicious Session",
            action_type=(
                ResponseActionType.TERMINATE_SESSION
            ),
            category=PlaybookCategory.IDENTITY,
            description=(
                "Terminate a specific suspicious authenticated "
                "session without disabling the complete account."
            ),
            default_approval_mode=(
                ApprovalMode.AUTOMATIC
            ),
            risk_level=ResponseRiskLevel.MEDIUM,
            reversible=False,
            estimated_execution_seconds=5,
            required_parameters=[
                "session_id",
            ],
            expected_effects=[
                "Interrupts the current attacker session",
            ],
            metadata={
                "safe_simulation_supported": True,
            },
        ),
        ResponseActionDefinition(
            action_id="ACT-SNAPSHOT-ASSET",
            name="Snapshot Asset State",
            action_type=(
                ResponseActionType.SNAPSHOT_ASSET
            ),
            category=PlaybookCategory.DATA_PROTECTION,
            description=(
                "Capture a safe forensic snapshot of the affected "
                "asset before disruptive containment."
            ),
            default_approval_mode=(
                ApprovalMode.AUTOMATIC
            ),
            risk_level=ResponseRiskLevel.LOW,
            reversible=False,
            estimated_execution_seconds=45,
            required_parameters=[
                "asset_id",
            ],
            expected_effects=[
                "Preserves evidence for investigation",
                "Supports later rollback or recovery",
            ],
            metadata={
                "safe_simulation_supported": True,
            },
        ),
        ResponseActionDefinition(
            action_id="ACT-ENHANCED-MONITORING",
            name="Enable Enhanced Monitoring",
            action_type=(
                ResponseActionType
                .ENABLE_ENHANCED_MONITORING
            ),
            category=PlaybookCategory.MONITORING,
            description=(
                "Increase telemetry collection and detection "
                "sensitivity for the selected target."
            ),
            default_approval_mode=(
                ApprovalMode.AUTOMATIC
            ),
            risk_level=ResponseRiskLevel.LOW,
            reversible=True,
            estimated_execution_seconds=5,
            required_parameters=[
                "target_id",
            ],
            expected_effects=[
                "Improves visibility during investigation",
            ],
            metadata={
                "safe_simulation_supported": True,
            },
        ),
        ResponseActionDefinition(
            action_id="ACT-RESTRICT-DATABASE",
            name="Restrict Database Access",
            action_type=(
                ResponseActionType
                .RESTRICT_DATABASE_ACCESS
            ),
            category=PlaybookCategory.DATA_PROTECTION,
            description=(
                "Apply temporary least-privilege restrictions "
                "to sensitive database access."
            ),
            default_approval_mode=(
                ApprovalMode
                .DUAL_APPROVAL_REQUIRED
            ),
            risk_level=ResponseRiskLevel.CRITICAL,
            reversible=True,
            estimated_execution_seconds=30,
            required_parameters=[
                "database_id",
                "identity_id",
            ],
            expected_effects=[
                "Prevents bulk sensitive-data access",
                "May affect legitimate examination operations",
            ],
            metadata={
                "safe_simulation_supported": True,
            },
        ),
        ResponseActionDefinition(
            action_id="ACT-PROTECT-BACKUP",
            name="Protect Backup Infrastructure",
            action_type=(
                ResponseActionType.PROTECT_BACKUP
            ),
            category=PlaybookCategory.DATA_PROTECTION,
            description=(
                "Place backup infrastructure into a protected "
                "state against destructive modification."
            ),
            default_approval_mode=(
                ApprovalMode.HUMAN_REQUIRED
            ),
            risk_level=ResponseRiskLevel.HIGH,
            reversible=True,
            estimated_execution_seconds=30,
            required_parameters=[
                "backup_id",
            ],
            expected_effects=[
                "Reduces ransomware and destructive-impact risk",
            ],
            metadata={
                "safe_simulation_supported": True,
            },
        ),
        ResponseActionDefinition(
            action_id="ACT-NOTIFY-SOC",
            name="Notify SOC",
            action_type=ResponseActionType.NOTIFY_SOC,
            category=PlaybookCategory.COORDINATION,
            description=(
                "Create an immediate SOC notification containing "
                "incident and action context."
            ),
            default_approval_mode=(
                ApprovalMode.AUTOMATIC
            ),
            risk_level=ResponseRiskLevel.LOW,
            reversible=False,
            estimated_execution_seconds=1,
            required_parameters=[],
            expected_effects=[
                "Escalates the incident to human responders",
            ],
            metadata={
                "safe_simulation_supported": True,
            },
        ),
    ]


def build_default_playbooks() -> list[
    ResponsePlaybook
]:
    return [
        ResponsePlaybook(
            playbook_id="PB-COMPROMISED-ENDPOINT",
            name="Compromised Endpoint Containment",
            description=(
                "Preserve endpoint evidence, isolate the device, "
                "revoke exposed credentials, and notify the SOC."
            ),
            supported_tactics=[
                "Execution",
                "Credential Access",
                "Lateral Movement",
            ],
            supported_severities=[
                "high",
                "critical",
            ],
            steps=[
                ResponsePlaybookStep(
                    step_number=1,
                    action_id="ACT-SNAPSHOT-ASSET",
                    action_type=(
                        ResponseActionType.SNAPSHOT_ASSET
                    ),
                    title="Preserve endpoint evidence",
                    description=(
                        "Create a safe forensic snapshot before "
                        "network isolation."
                    ),
                    approval_mode=ApprovalMode.AUTOMATIC,
                    risk_level=ResponseRiskLevel.LOW,
                    parameters={},
                    continue_on_failure=True,
                    reversible=False,
                ),
                ResponsePlaybookStep(
                    step_number=2,
                    action_id="ACT-ISOLATE-ENDPOINT",
                    action_type=(
                        ResponseActionType.ISOLATE_ENDPOINT
                    ),
                    title="Isolate compromised endpoint",
                    description=(
                        "Restrict endpoint communication while "
                        "retaining SOC access."
                    ),
                    approval_mode=(
                        ApprovalMode.HUMAN_REQUIRED
                    ),
                    risk_level=ResponseRiskLevel.HIGH,
                    parameters={},
                    continue_on_failure=False,
                    reversible=True,
                ),
                ResponsePlaybookStep(
                    step_number=3,
                    action_id="ACT-REVOKE-CREDENTIALS",
                    action_type=(
                        ResponseActionType.REVOKE_CREDENTIALS
                    ),
                    title="Revoke exposed credentials",
                    description=(
                        "Terminate identity sessions and require "
                        "credential rotation."
                    ),
                    approval_mode=(
                        ApprovalMode.HUMAN_REQUIRED
                    ),
                    risk_level=ResponseRiskLevel.HIGH,
                    parameters={},
                    continue_on_failure=False,
                    reversible=False,
                ),
                ResponsePlaybookStep(
                    step_number=4,
                    action_id="ACT-NOTIFY-SOC",
                    action_type=(
                        ResponseActionType.NOTIFY_SOC
                    ),
                    title="Notify SOC responders",
                    description=(
                        "Create an immediate incident notification."
                    ),
                    approval_mode=ApprovalMode.AUTOMATIC,
                    risk_level=ResponseRiskLevel.LOW,
                    parameters={},
                    continue_on_failure=True,
                    reversible=False,
                ),
            ],
            tags=[
                "endpoint",
                "credential-access",
                "lateral-movement",
            ],
        ),
        ResponsePlaybook(
            playbook_id="PB-DATA-EXFILTRATION",
            name="Sensitive Data Exfiltration Response",
            description=(
                "Restrict database access, block external "
                "communication, preserve evidence, and protect backups."
            ),
            supported_tactics=[
                "Collection",
                "Command and Control",
                "Exfiltration",
            ],
            supported_severities=[
                "high",
                "critical",
            ],
            steps=[
                ResponsePlaybookStep(
                    step_number=1,
                    action_id="ACT-SNAPSHOT-ASSET",
                    action_type=(
                        ResponseActionType.SNAPSHOT_ASSET
                    ),
                    title="Preserve database evidence",
                    description=(
                        "Snapshot the affected data system."
                    ),
                    approval_mode=ApprovalMode.AUTOMATIC,
                    risk_level=ResponseRiskLevel.LOW,
                    parameters={},
                    continue_on_failure=True,
                    reversible=False,
                ),
                ResponsePlaybookStep(
                    step_number=2,
                    action_id="ACT-BLOCK-IP",
                    action_type=ResponseActionType.BLOCK_IP,
                    title="Block exfiltration destination",
                    description=(
                        "Apply a temporary block to the suspicious "
                        "external destination."
                    ),
                    approval_mode=ApprovalMode.AUTOMATIC,
                    risk_level=ResponseRiskLevel.MEDIUM,
                    parameters={},
                    continue_on_failure=False,
                    reversible=True,
                ),
                ResponsePlaybookStep(
                    step_number=3,
                    action_id="ACT-RESTRICT-DATABASE",
                    action_type=(
                        ResponseActionType
                        .RESTRICT_DATABASE_ACCESS
                    ),
                    title="Restrict sensitive database access",
                    description=(
                        "Apply temporary least-privilege controls."
                    ),
                    approval_mode=(
                        ApprovalMode
                        .DUAL_APPROVAL_REQUIRED
                    ),
                    risk_level=ResponseRiskLevel.CRITICAL,
                    parameters={},
                    continue_on_failure=False,
                    reversible=True,
                ),
                ResponsePlaybookStep(
                    step_number=4,
                    action_id="ACT-PROTECT-BACKUP",
                    action_type=(
                        ResponseActionType.PROTECT_BACKUP
                    ),
                    title="Protect backup infrastructure",
                    description=(
                        "Prevent destructive modification of backups."
                    ),
                    approval_mode=(
                        ApprovalMode.HUMAN_REQUIRED
                    ),
                    risk_level=ResponseRiskLevel.HIGH,
                    parameters={},
                    continue_on_failure=True,
                    reversible=True,
                ),
                ResponsePlaybookStep(
                    step_number=5,
                    action_id="ACT-NOTIFY-SOC",
                    action_type=(
                        ResponseActionType.NOTIFY_SOC
                    ),
                    title="Notify SOC responders",
                    description=(
                        "Escalate the exfiltration incident."
                    ),
                    approval_mode=ApprovalMode.AUTOMATIC,
                    risk_level=ResponseRiskLevel.LOW,
                    parameters={},
                    continue_on_failure=True,
                    reversible=False,
                ),
            ],
            tags=[
                "database",
                "collection",
                "exfiltration",
            ],
        ),
        ResponsePlaybook(
            playbook_id="PB-LOW-CONFIDENCE-MONITOR",
            name="Low-Confidence Enhanced Monitoring",
            description=(
                "Increase monitoring and notify analysts without "
                "performing disruptive containment."
            ),
            supported_tactics=[
                "Initial Access",
                "Execution",
                "Discovery",
            ],
            supported_severities=[
                "low",
                "medium",
            ],
            steps=[
                ResponsePlaybookStep(
                    step_number=1,
                    action_id="ACT-ENHANCED-MONITORING",
                    action_type=(
                        ResponseActionType
                        .ENABLE_ENHANCED_MONITORING
                    ),
                    title="Increase telemetry collection",
                    description=(
                        "Apply enhanced monitoring to the target."
                    ),
                    approval_mode=ApprovalMode.AUTOMATIC,
                    risk_level=ResponseRiskLevel.LOW,
                    parameters={},
                    continue_on_failure=True,
                    reversible=True,
                ),
                ResponsePlaybookStep(
                    step_number=2,
                    action_id="ACT-NOTIFY-SOC",
                    action_type=(
                        ResponseActionType.NOTIFY_SOC
                    ),
                    title="Notify SOC for review",
                    description=(
                        "Send the observation to a human analyst."
                    ),
                    approval_mode=ApprovalMode.AUTOMATIC,
                    risk_level=ResponseRiskLevel.LOW,
                    parameters={},
                    continue_on_failure=True,
                    reversible=False,
                ),
            ],
            tags=[
                "monitoring",
                "non-disruptive",
                "human-review",
            ],
        ),
    ]


class PlaybookRegistry:
    def __init__(self) -> None:
        self._actions: dict[
            str,
            ResponseActionDefinition,
        ] = {}

        self._playbooks: dict[
            str,
            ResponsePlaybook,
        ] = {}

        self._lock = RLock()

    def load_defaults(self) -> None:
        with self._lock:
            self.clear()

            for action in build_default_actions():
                self.register_action(action)

            for playbook in build_default_playbooks():
                self.register_playbook(playbook)

    def register_action(
        self,
        action: ResponseActionDefinition,
    ) -> ResponseActionDefinition:
        with self._lock:
            if action.action_id in self._actions:
                raise ValueError(
                    f"Action already exists: {action.action_id}"
                )

            self._actions[action.action_id] = action
            return action

    def register_playbook(
        self,
        playbook: ResponsePlaybook,
    ) -> ResponsePlaybook:
        with self._lock:
            if playbook.playbook_id in self._playbooks:
                raise ValueError(
                    "Playbook already exists: "
                    f"{playbook.playbook_id}"
                )

            step_numbers = [
                step.step_number
                for step in playbook.steps
            ]

            expected_numbers = list(
                range(
                    1,
                    len(playbook.steps) + 1,
                )
            )

            if step_numbers != expected_numbers:
                raise ValueError(
                    "Playbook steps must use contiguous "
                    "step numbers beginning at 1"
                )

            for step in playbook.steps:
                action = self._actions.get(
                    step.action_id
                )

                if action is None:
                    raise ValueError(
                        "Playbook references unknown action: "
                        f"{step.action_id}"
                    )

                if (
                    action.action_type
                    != step.action_type
                ):
                    raise ValueError(
                        "Playbook action type does not match "
                        f"registry action: {step.action_id}"
                    )

            self._playbooks[
                playbook.playbook_id
            ] = playbook

            return playbook

    def get_action(
        self,
        action_id: str,
    ) -> ResponseActionDefinition | None:
        with self._lock:
            return self._actions.get(action_id)

    def require_action(
        self,
        action_id: str,
    ) -> ResponseActionDefinition:
        action = self.get_action(action_id)

        if action is None:
            raise KeyError(
                f"Response action not found: {action_id}"
            )

        return action

    def get_playbook(
        self,
        playbook_id: str,
    ) -> ResponsePlaybook | None:
        with self._lock:
            return self._playbooks.get(
                playbook_id
            )

    def require_playbook(
        self,
        playbook_id: str,
    ) -> ResponsePlaybook:
        playbook = self.get_playbook(
            playbook_id
        )

        if playbook is None:
            raise KeyError(
                f"Response playbook not found: {playbook_id}"
            )

        return playbook

    def actions(
        self,
        enabled_only: bool = False,
    ) -> list[ResponseActionDefinition]:
        with self._lock:
            actions = list(
                self._actions.values()
            )

            if enabled_only:
                actions = [
                    action
                    for action in actions
                    if action.enabled
                ]

            return sorted(
                actions,
                key=lambda action: action.action_id,
            )

    def playbooks(
        self,
        enabled_only: bool = False,
    ) -> list[ResponsePlaybook]:
        with self._lock:
            playbooks = list(
                self._playbooks.values()
            )

            if enabled_only:
                playbooks = [
                    playbook
                    for playbook in playbooks
                    if playbook.enabled
                ]

            return sorted(
                playbooks,
                key=lambda playbook: (
                    playbook.playbook_id
                ),
            )

    def recommend_playbooks(
        self,
        tactic: str,
        severity: str,
    ) -> list[ResponsePlaybook]:
        normalised_tactic = tactic.strip().lower()
        normalised_severity = (
            severity.strip().lower()
        )

        matches = [
            playbook
            for playbook in self.playbooks(
                enabled_only=True
            )
            if normalised_tactic
            in {
                value.lower()
                for value in playbook.supported_tactics
            }
            and normalised_severity
            in {
                value.lower()
                for value
                in playbook.supported_severities
            }
        ]

        return sorted(
            matches,
            key=lambda playbook: (
                len(playbook.steps),
                playbook.playbook_id,
            ),
        )

    def summary(
        self,
    ) -> PlaybookRegistrySummary:
        with self._lock:
            actions = self.actions()
            playbooks = self.playbooks()

            return PlaybookRegistrySummary(
                action_count=len(actions),
                playbook_count=len(playbooks),
                enabled_action_count=sum(
                    1
                    for action in actions
                    if action.enabled
                ),
                enabled_playbook_count=sum(
                    1
                    for playbook in playbooks
                    if playbook.enabled
                ),
                action_types=sorted(
                    {
                        action.action_type
                        for action in actions
                    },
                    key=lambda value: value.value,
                ),
                playbook_ids=[
                    playbook.playbook_id
                    for playbook in playbooks
                ],
            )

    def clear(self) -> None:
        with self._lock:
            self._actions.clear()
            self._playbooks.clear()


playbook_registry = PlaybookRegistry()
playbook_registry.load_defaults()