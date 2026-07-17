from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app
from app.response import (
    response_orchestration_service,
)


client = TestClient(app)


def setup_function() -> None:
    response_orchestration_service.reset()


def create_execution() -> dict:
    response = client.post(
        "/api/response/executions",
        json={
            "incident_id": "INC-API-001",
            "playbook_id": (
                "PB-COMPROMISED-ENDPOINT"
            ),
            "requested_by": "soc.requester",
            "targets": [
                {
                    "target_id": "DEV-018",
                    "target_type": (
                        "workstation"
                    ),
                },
                {
                    "target_id": "USR-104",
                    "target_type": "user",
                },
            ],
            "context": {
                "severity": "critical",
            },
            "dry_run": True,
        },
    )

    assert response.status_code == 201
    return response.json()


def test_response_health() -> None:
    response = client.get(
        "/api/response/health"
    )

    assert response.status_code == 200
    assert response.json()[
        "simulation_only"
    ] is True


def test_list_response_playbooks() -> None:
    response = client.get(
        "/api/response/playbooks"
    )

    assert response.status_code == 200
    assert len(response.json()) == 3


def test_create_and_retrieve_execution() -> None:
    payload = create_execution()

    execution_id = payload[
        "execution_id"
    ]

    response = client.get(
        f"/api/response/executions/"
        f"{execution_id}"
    )

    assert response.status_code == 200

    assert response.json()[
        "execution_id"
    ] == execution_id


def test_automatic_steps_execute_first() -> None:
    payload = create_execution()

    execution_id = payload[
        "execution_id"
    ]

    response = client.post(
        f"/api/response/executions/"
        f"{execution_id}/execute"
    )

    assert response.status_code == 200

    result = response.json()

    assert result["status"] == (
        "pending_approval"
    )

    assert result["steps"][0][
        "status"
    ] == "completed"


def test_approval_and_execution_flow() -> None:
    payload = create_execution()

    execution_id = payload[
        "execution_id"
    ]

    human_steps = [
        step
        for step in payload["steps"]
        if step[
            "required_approval_count"
        ] > 0
    ]

    for step in human_steps:
        response = client.post(
            f"/api/response/executions/"
            f"{execution_id}/approve",
            json={
                "execution_step_id": (
                    step[
                        "execution_step_id"
                    ]
                ),
                "approver_id": (
                    "analyst-"
                    f"{step['step_number']}"
                ),
                "approved": True,
                "reason": (
                    "Approved after SOC review"
                ),
            },
        )

        assert response.status_code == 200

    response = client.post(
        f"/api/response/executions/"
        f"{execution_id}/execute"
    )

    assert response.status_code == 200

    result = response.json()

    assert result["status"] == "completed"

    assert all(
        step["status"] == "completed"
        for step in result["steps"]
    )


def test_audit_ledger_verifies() -> None:
    payload = create_execution()

    execution_id = payload[
        "execution_id"
    ]

    client.post(
        f"/api/response/executions/"
        f"{execution_id}/execute"
    )

    response = client.get(
        "/api/response/audit/verify"
    )

    assert response.status_code == 200
    assert response.json()["valid"] is True
    assert response.json()[
        "record_count"
    ] > 0