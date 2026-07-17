from __future__ import annotations

import json
from pathlib import Path

from app.prediction.service import (
    PredictiveAttackService,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]

SCENARIO_PATH = (
    PROJECT_ROOT
    / "event-simulator"
    / "datasets"
    / "silent_intruder_events.json"
)


def load_malicious_events() -> list[dict]:
    with SCENARIO_PATH.open(
        "r",
        encoding="utf-8",
    ) as file:
        events = json.load(file)

    return [
        event
        for event in events
        if event.get("label") == "malicious"
    ]


def test_predict_after_credential_access() -> None:
    events = load_malicious_events()

    service = PredictiveAttackService()

    result = service.predict(
        events=events[:4],
        horizon=3,
        source_node_id="DEV-018",
    )

    assert result.current_tactic == (
        "Credential Access"
    )

    assert result.most_likely_next_tactic == (
        "Discovery"
    )

    assert [
        stage.tactic
        for stage in result.predicted_stages
    ] == [
        "Discovery",
        "Lateral Movement",
        "Collection",
    ]

    assert result.confidence > 0


def test_predict_after_collection() -> None:
    events = load_malicious_events()

    service = PredictiveAttackService()

    result = service.predict(
        events=events[:7],
        horizon=1,
        source_node_id="EXAM-APP-01",
    )

    assert result.current_tactic == "Collection"

    assert result.most_likely_next_tactic == (
        "Exfiltration"
    )


def test_prediction_includes_defensive_actions() -> None:
    events = load_malicious_events()

    service = PredictiveAttackService()

    result = service.predict(
        events=events[:4],
        horizon=1,
        source_node_id="DEV-018",
    )

    assert result.predicted_stages
    assert (
        result.predicted_stages[0]
        .recommended_defensive_actions
    )


def test_sequence_evaluation() -> None:
    events = load_malicious_events()

    service = PredictiveAttackService()

    evaluation = service.evaluate_sequence(
        events
    )

    assert evaluation.evaluated_prefixes >= 6
    assert 0.0 <= evaluation.top_one_accuracy <= 1.0
    assert evaluation.predictions