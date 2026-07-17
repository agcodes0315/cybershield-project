from __future__ import annotations

from copy import deepcopy

from .schemas import (
    TransitionMatrixSummary,
    TransitionProbability,
)


DEFAULT_TRANSITION_MATRIX: dict[
    str,
    dict[str, float],
] = {
    "Initial Access": {
        "Execution": 0.55,
        "Credential Access": 0.25,
        "Persistence": 0.20,
    },
    "Execution": {
        "Credential Access": 0.40,
        "Persistence": 0.20,
        "Defense Evasion": 0.20,
        "Discovery": 0.20,
    },
    "Persistence": {
        "Privilege Escalation": 0.35,
        "Defense Evasion": 0.30,
        "Credential Access": 0.20,
        "Discovery": 0.15,
    },
    "Privilege Escalation": {
        "Defense Evasion": 0.30,
        "Credential Access": 0.40,
        "Discovery": 0.30,
    },
    "Defense Evasion": {
        "Credential Access": 0.35,
        "Discovery": 0.35,
        "Lateral Movement": 0.30,
    },
    "Credential Access": {
        "Discovery": 0.50,
        "Lateral Movement": 0.30,
        "Collection": 0.20,
    },
    "Discovery": {
        "Lateral Movement": 0.60,
        "Collection": 0.25,
        "Command and Control": 0.15,
    },
    "Lateral Movement": {
        "Collection": 0.55,
        "Credential Access": 0.15,
        "Exfiltration": 0.15,
        "Impact": 0.15,
    },
    "Collection": {
        "Exfiltration": 0.65,
        "Command and Control": 0.20,
        "Impact": 0.15,
    },
    "Command and Control": {
        "Exfiltration": 0.60,
        "Impact": 0.40,
    },
    "Exfiltration": {
        "Impact": 0.70,
        "Command and Control": 0.30,
    },
    "Impact": {
        "Impact": 1.00,
    },
}


class AttackTransitionModel:
    """
    MITRE ATT&CK tactic transition model.

    The model can use the default expert matrix and can also learn
    additional transition counts from labelled tactic sequences.
    """

    def __init__(
        self,
        transition_matrix: dict[
            str,
            dict[str, float],
        ]
        | None = None,
    ) -> None:
        self._matrix = deepcopy(
            transition_matrix
            or DEFAULT_TRANSITION_MATRIX
        )

        self.validate()

    def validate(self) -> None:
        for source_tactic, transitions in self._matrix.items():
            if not transitions:
                raise ValueError(
                    f"No transitions configured for {source_tactic}"
                )

            total = sum(transitions.values())

            if abs(total - 1.0) > 0.000001:
                raise ValueError(
                    "Transition probabilities for "
                    f"{source_tactic} must sum to 1.0; "
                    f"received {total:.6f}"
                )

            for target_tactic, probability in transitions.items():
                if not 0.0 <= probability <= 1.0:
                    raise ValueError(
                        "Invalid transition probability for "
                        f"{source_tactic}->{target_tactic}: "
                        f"{probability}"
                    )

    def probability(
        self,
        source_tactic: str,
        target_tactic: str,
    ) -> float:
        return float(
            self._matrix
            .get(source_tactic, {})
            .get(target_tactic, 0.0)
        )

    def next_tactics(
        self,
        source_tactic: str,
    ) -> list[tuple[str, float]]:
        transitions = self._matrix.get(
            source_tactic,
            {}
        )

        return sorted(
            transitions.items(),
            key=lambda item: (
                -item[1],
                item[0],
            ),
        )

    def tactics(self) -> list[str]:
        values = set(self._matrix)

        for transitions in self._matrix.values():
            values.update(transitions)

        return sorted(values)

    def matrix(
        self,
    ) -> dict[str, dict[str, float]]:
        return deepcopy(self._matrix)

    def learn_from_sequences(
        self,
        sequences: list[list[str]],
        smoothing: float = 1.0,
    ) -> None:
        if smoothing < 0:
            raise ValueError(
                "smoothing cannot be negative"
            )

        tactic_names = set(self.tactics())

        for sequence in sequences:
            tactic_names.update(sequence)

        counts: dict[str, dict[str, float]] = {}

        for source_tactic in tactic_names:
            known_targets = set(
                self._matrix.get(
                    source_tactic,
                    {},
                )
            )

            counts[source_tactic] = {
                target_tactic: smoothing
                for target_tactic in known_targets
            }

        for sequence in sequences:
            for index in range(len(sequence) - 1):
                source_tactic = sequence[index]
                target_tactic = sequence[index + 1]

                counts.setdefault(
                    source_tactic,
                    {},
                )

                counts[source_tactic][target_tactic] = (
                    counts[source_tactic].get(
                        target_tactic,
                        smoothing,
                    )
                    + 1.0
                )

        learned_matrix: dict[
            str,
            dict[str, float],
        ] = {}

        for source_tactic, target_counts in counts.items():
            if not target_counts:
                continue

            total = sum(target_counts.values())

            learned_matrix[source_tactic] = {
                target_tactic: count / total
                for target_tactic, count
                in target_counts.items()
            }

        for source_tactic, transitions in self._matrix.items():
            if source_tactic not in learned_matrix:
                learned_matrix[source_tactic] = deepcopy(
                    transitions
                )

        self._matrix = learned_matrix
        self.validate()

    def summary(self) -> TransitionMatrixSummary:
        transitions: list[TransitionProbability] = []

        for source_tactic in sorted(self._matrix):
            for target_tactic, probability in sorted(
                self._matrix[source_tactic].items()
            ):
                transitions.append(
                    TransitionProbability(
                        source_tactic=source_tactic,
                        target_tactic=target_tactic,
                        probability=round(
                            probability,
                            6,
                        ),
                    )
                )

        return TransitionMatrixSummary(
            tactic_count=len(self.tactics()),
            transition_count=len(transitions),
            transitions=transitions,
        )