import json
from pathlib import Path

from app.ueba.service import UEBAService


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATASET_DIR = PROJECT_ROOT / "event-simulator" / "datasets"


def load_events(filename: str):
    path = DATASET_DIR / filename

    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def test_ueba_detects_silent_intruder(tmp_path) -> None:
    normal_events = load_events(
        "normal_events.json"
    )

    scenario_events = load_events(
        "silent_intruder_events.json"
    )

    service = UEBAService(
        contamination=0.05,
        model_path=tmp_path / "ueba.joblib",
    )

    summary = service.train(
        normal_events,
        save_model=True,
    )

    assert summary.trained is True
    assert summary.event_count == 250

    malicious_events = [
        event
        for event in scenario_events
        if event.get("label") == "malicious"
    ]

    results = service.analyse_batch(
        malicious_events
    )

    assert len(results) == 8

    detected = sum(
        result.is_anomalous
        for result in results
    )

    assert detected >= 5

    highest_result = max(
        results,
        key=lambda result: result.anomaly_score,
    )

    assert highest_result.anomaly_score >= 0.60
    assert highest_result.reasons