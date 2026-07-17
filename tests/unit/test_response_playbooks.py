from __future__ import annotations

import pytest

from app.response.playbooks import (
    PlaybookRegistry,
    build_default_actions,
    build_default_playbooks,
)
from app.response.schemas import (
    ApprovalMode,
    PlaybookCategory,
    ResponseActionDefinition,
    ResponseActionType,
    ResponsePlaybook,
    ResponsePlaybookStep,
    ResponseRiskLevel,
)


def build_registry() -> PlaybookRegistry:
    registry = PlaybookRegistry()

    for action in build_default_actions():
        registry.register_action(action)

    for playbook in build_default_playbooks():
        registry.register_playbook(playbook)

    return registry


def test_default_registry_loads() -> None:
    registry = build_registry()

    summary = registry.summary()

    assert summary.action_count == 10
    assert summary.playbook_count == 3
    assert summary.enabled_action_count == 10
    assert summary.enabled_playbook_count == 3


def test_compromised_endpoint_playbook_exists() -> None:
    registry = build_registry()

    playbook = registry.require_playbook(
        "PB-COMPROMISED-ENDPOINT"
    )

    assert playbook.name == (
        "Compromised Endpoint Containment"
    )

    assert len(playbook.steps) == 4

    assert playbook.steps[0].action_type == (
        ResponseActionType.SNAPSHOT_ASSET
    )

    assert playbook.steps[1].approval_mode == (
        ApprovalMode.HUMAN_REQUIRED
    )


def test_exfiltration_playbook_requires_dual_approval() -> None:
    registry = build_registry()

    playbook = registry.require_playbook(
        "PB-DATA-EXFILTRATION"
    )

    database_step = next(
        step
        for step in playbook.steps
        if step.action_type
        == ResponseActionType.RESTRICT_DATABASE_ACCESS
    )

    assert database_step.approval_mode == (
        ApprovalMode.DUAL_APPROVAL_REQUIRED
    )

    assert database_step.risk_level == (
        ResponseRiskLevel.CRITICAL
    )


def test_recommend_playbook_for_credential_access() -> None:
    registry = build_registry()

    recommendations = (
        registry.recommend_playbooks(
            tactic="Credential Access",
            severity="critical",
        )
    )

    assert recommendations

    assert recommendations[0].playbook_id == (
        "PB-COMPROMISED-ENDPOINT"
    )


def test_recommend_playbook_for_exfiltration() -> None:
    registry = build_registry()

    recommendations = (
        registry.recommend_playbooks(
            tactic="Exfiltration",
            severity="critical",
        )
    )

    assert recommendations

    assert recommendations[0].playbook_id == (
        "PB-DATA-EXFILTRATION"
    )


def test_low_confidence_monitoring_playbook() -> None:
    registry = build_registry()

    recommendations = (
        registry.recommend_playbooks(
            tactic="Discovery",
            severity="medium",
        )
    )

    assert recommendations

    assert recommendations[0].playbook_id == (
        "PB-LOW-CONFIDENCE-MONITOR"
    )


def test_duplicate_action_is_rejected() -> None:
    registry = PlaybookRegistry()

    action = ResponseActionDefinition(
        action_id="ACT-TEST",
        name="Test Action",
        action_type=ResponseActionType.NOTIFY_SOC,
        category=PlaybookCategory.COORDINATION,
        description="Test action",
        default_approval_mode=(
            ApprovalMode.AUTOMATIC
        ),
        risk_level=ResponseRiskLevel.LOW,
    )

    registry.register_action(action)

    with pytest.raises(
        ValueError,
        match="Action already exists",
    ):
        registry.register_action(action)


def test_unknown_action_in_playbook_is_rejected() -> None:
    registry = PlaybookRegistry()

    playbook = ResponsePlaybook(
        playbook_id="PB-INVALID",
        name="Invalid Playbook",
        description="References an unknown action",
        steps=[
            ResponsePlaybookStep(
                step_number=1,
                action_id="ACT-UNKNOWN",
                action_type=(
                    ResponseActionType.NOTIFY_SOC
                ),
                title="Unknown",
                description="Unknown action",
                approval_mode=ApprovalMode.AUTOMATIC,
                risk_level=ResponseRiskLevel.LOW,
            )
        ],
    )

    with pytest.raises(
        ValueError,
        match="unknown action",
    ):
        registry.register_playbook(playbook)


def test_non_contiguous_steps_are_rejected() -> None:
    registry = PlaybookRegistry()

    action = ResponseActionDefinition(
        action_id="ACT-TEST",
        name="Test Action",
        action_type=ResponseActionType.NOTIFY_SOC,
        category=PlaybookCategory.COORDINATION,
        description="Test action",
        default_approval_mode=(
            ApprovalMode.AUTOMATIC
        ),
        risk_level=ResponseRiskLevel.LOW,
    )

    registry.register_action(action)

    playbook = ResponsePlaybook(
        playbook_id="PB-BROKEN-STEPS",
        name="Broken Steps",
        description="Invalid numbering",
        steps=[
            ResponsePlaybookStep(
                step_number=2,
                action_id="ACT-TEST",
                action_type=(
                    ResponseActionType.NOTIFY_SOC
                ),
                title="Notify",
                description="Notify SOC",
                approval_mode=ApprovalMode.AUTOMATIC,
                risk_level=ResponseRiskLevel.LOW,
            )
        ],
    )

    with pytest.raises(
        ValueError,
        match="contiguous",
    ):
        registry.register_playbook(playbook)


def test_unknown_registry_items_raise_key_error() -> None:
    registry = build_registry()

    with pytest.raises(
        KeyError,
        match="Response action not found",
    ):
        registry.require_action(
            "ACT-DOES-NOT-EXIST"
        )

    with pytest.raises(
        KeyError,
        match="Response playbook not found",
    ):
        registry.require_playbook(
            "PB-DOES-NOT-EXIST"
        )