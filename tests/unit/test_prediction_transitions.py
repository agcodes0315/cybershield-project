from __future__ import annotations

import pytest

from app.prediction.transitions import (
    AttackTransitionModel,
)


def test_transition_probabilities_sum_to_one() -> None:
    model = AttackTransitionModel()

    for tactic in model.tactics():
        transitions = model.next_tactics(
            tactic
        )

        if not transitions:
            continue

        assert sum(
            probability
            for _, probability in transitions
        ) == pytest.approx(1.0)


def test_expected_credential_access_transition() -> None:
    model = AttackTransitionModel()

    transitions = model.next_tactics(
        "Credential Access"
    )

    assert transitions[0] == (
        "Discovery",
        0.50,
    )


def test_invalid_matrix_is_rejected() -> None:
    with pytest.raises(
        ValueError,
        match="must sum to 1.0",
    ):
        AttackTransitionModel(
            {
                "Initial Access": {
                    "Execution": 0.40,
                    "Discovery": 0.40,
                }
            }
        )


def test_summary_contains_transitions() -> None:
    model = AttackTransitionModel()

    summary = model.summary()

    assert summary.tactic_count > 0
    assert summary.transition_count > 0
    assert summary.transitions