from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DATASET_DIRECTORY = PROJECT_ROOT / "event-simulator" / "datasets"


class SecurityEventSimulator:
    """Generate safe synthetic telemetry for CyberShield CNI."""

    def __init__(self, random_seed: int = 42) -> None:
        self.random = random.Random(random_seed)
        self.event_counter = 0

    def next_event_id(self, prefix: str) -> str:
        self.event_counter += 1
        return f"EVT-{prefix}-{self.event_counter:06d}"

    def generate_normal_events(
        self,
        count: int = 250,
        start_time: datetime | None = None,
    ) -> list[dict[str, Any]]:
        if count <= 0:
            raise ValueError("count must be greater than zero")

        base_time = start_time or datetime.now(timezone.utc)

        users = [
            {
                "user_id": "USR-101",
                "username": "rahul.verma",
                "device_id": "DEV-011",
                "department": "IT Security",
                "source_ip": "10.0.1.11",
            },
            {
                "user_id": "USR-102",
                "username": "meera.iyer",
                "device_id": "DEV-012",
                "department": "Digital Services",
                "source_ip": "10.0.1.12",
            },
            {
                "user_id": "USR-103",
                "username": "vikram.singh",
                "device_id": "DEV-013",
                "department": "Infrastructure",
                "source_ip": "10.0.1.13",
            },
            {
                "user_id": "USR-104",
                "username": "anita.sharma",
                "device_id": "DEV-018",
                "department": "Examinations",
                "source_ip": "10.0.1.18",
            },
        ]

        event_types = [
            "login_success",
            "application_access",
            "file_read",
            "dns_query",
            "internal_connection",
            "logout",
        ]

        assets = [
            "IDP-001",
            "PORTAL-001",
            "EXAM-APP-01",
            "BACKUP-01",
            "SOC-001",
        ]

        events: list[dict[str, Any]] = []

        for index in range(count):
            user = self.random.choice(users)
            event_type = self.random.choice(event_types)
            timestamp = base_time + timedelta(minutes=index * 2)

            events.append(
                {
                    "event_id": self.next_event_id("NORMAL"),
                    "timestamp": timestamp.isoformat(),
                    "source_type": self.source_for_event(event_type),
                    "event_type": event_type,
                    "severity": "info",
                    "organisation_id": "ORG-DEMO-001",
                    "user_id": user["user_id"],
                    "username": user["username"],
                    "device_id": user["device_id"],
                    "department": user["department"],
                    "source_ip": user["source_ip"],
                    "asset_id": self.random.choice(assets),
                    "anomaly_score": round(
                        self.random.uniform(0.01, 0.20),
                        4,
                    ),
                    "confidence": round(
                        self.random.uniform(0.85, 0.99),
                        4,
                    ),
                    "label": "normal",
                    "scenario_id": "NORMAL-BASELINE",
                    "attributes": {
                        "login_hour": self.random.randint(9, 18),
                        "new_device": False,
                        "new_location": False,
                        "failed_login_count": self.random.randint(0, 1),
                        "encoded_command": False,
                        "privileged_action": False,
                        "data_transfer_mb": round(
                            self.random.uniform(0.5, 25.0),
                            2,
                        ),
                    },
                    "tags": ["synthetic", "normal"],
                }
            )

        return events

    def generate_silent_intruder(
        self,
        start_time: datetime | None = None,
    ) -> list[dict[str, Any]]:
        base_time = start_time or datetime.now(timezone.utc)

        events: list[dict[str, Any]] = []

        # Twelve normal events establish the compromised user's baseline.
        for index in range(12):
            events.append(
                {
                    "event_id": self.next_event_id("BASELINE"),
                    "timestamp": (
                        base_time
                        - timedelta(hours=5)
                        + timedelta(minutes=index * 15)
                    ).isoformat(),
                    "source_type": "authentication",
                    "event_type": "login_success",
                    "severity": "info",
                    "organisation_id": "ORG-DEMO-001",
                    "user_id": "USR-104",
                    "username": "anita.sharma",
                    "device_id": "DEV-018",
                    "department": "Examinations",
                    "source_ip": "10.0.1.18",
                    "asset_id": "EXAM-APP-01",
                    "anomaly_score": round(
                        self.random.uniform(0.02, 0.14),
                        4,
                    ),
                    "confidence": 0.95,
                    "label": "normal",
                    "scenario_id": "USER-BASELINE",
                    "attributes": {
                        "login_hour": 10 + (index % 7),
                        "new_device": False,
                        "new_location": False,
                        "failed_login_count": 0,
                        "encoded_command": False,
                        "data_transfer_mb": round(
                            self.random.uniform(1.0, 18.0),
                            2,
                        ),
                    },
                    "tags": ["synthetic", "baseline"],
                }
            )

        attack_definitions = [
            {
                "minutes": 0,
                "stage": 1,
                "source_type": "email",
                "event_type": "phishing_email_detected",
                "severity": "medium",
                "asset_id": "DEV-018",
                "source_ip": "203.0.113.25",
                "anomaly_score": 0.61,
                "confidence": 0.92,
                "attributes": {
                    "spf_result": "fail",
                    "dkim_result": "fail",
                    "dmarc_result": "fail",
                    "user_clicked": True,
                },
            },
            {
                "minutes": 8,
                "stage": 2,
                "source_type": "authentication",
                "event_type": "login_success",
                "severity": "medium",
                "asset_id": "IDP-001",
                "source_ip": "203.0.113.25",
                "anomaly_score": 0.78,
                "confidence": 0.88,
                "attributes": {
                    "login_hour": 2,
                    "new_device": True,
                    "new_location": True,
                    "failed_login_count": 6,
                    "mfa_used": False,
                    "impossible_travel": True,
                },
            },
            {
                "minutes": 14,
                "stage": 3,
                "source_type": "endpoint",
                "event_type": "process_execution",
                "severity": "high",
                "asset_id": "DEV-018",
                "source_ip": "10.0.1.18",
                "anomaly_score": 0.88,
                "confidence": 0.93,
                "attributes": {
                    "process_name": "powershell.exe",
                    "parent_process": "winword.exe",
                    "encoded_command": True,
                    "user_normally_uses_powershell": False,
                },
            },
            {
                "minutes": 22,
                "stage": 4,
                "source_type": "endpoint",
                "event_type": "credential_dumping",
                "severity": "critical",
                "asset_id": "DEV-018",
                "source_ip": "10.0.1.18",
                "anomaly_score": 0.96,
                "confidence": 0.95,
                "attributes": {
                    "target_process": "lsass.exe",
                    "memory_access": True,
                    "privilege_escalation_observed": True,
                },
            },
            {
                "minutes": 31,
                "stage": 5,
                "source_type": "network",
                "event_type": "network_service_discovery",
                "severity": "high",
                "asset_id": "EXAM-APP-01",
                "source_ip": "10.0.1.18",
                "anomaly_score": 0.84,
                "confidence": 0.90,
                "attributes": {
                    "destination_count": 24,
                    "port_count": 16,
                    "previously_contacted_asset": False,
                },
            },
            {
                "minutes": 43,
                "stage": 6,
                "source_type": "network",
                "event_type": "remote_service_connection",
                "severity": "critical",
                "asset_id": "EXAM-APP-01",
                "source_ip": "10.0.1.18",
                "anomaly_score": 0.93,
                "confidence": 0.94,
                "attributes": {
                    "protocol": "RDP",
                    "service_account_used": True,
                    "first_time_connection": True,
                },
            },
            {
                "minutes": 56,
                "stage": 7,
                "source_type": "endpoint",
                "event_type": "sensitive_database_access",
                "severity": "critical",
                "asset_id": "EXAM-DB-01",
                "source_ip": "10.0.3.20",
                "anomaly_score": 0.97,
                "confidence": 0.96,
                "attributes": {
                    "records_accessed": 18432,
                    "query_type": "bulk_select",
                    "access_outside_role": True,
                },
            },
            {
                "minutes": 68,
                "stage": 8,
                "source_type": "network",
                "event_type": "unusual_data_transfer",
                "severity": "critical",
                "asset_id": "EXAM-DB-01",
                "source_ip": "10.0.3.20",
                "anomaly_score": 0.99,
                "confidence": 0.97,
                "attributes": {
                    "data_transfer_mb": 742.8,
                    "normal_transfer_mb": 12.4,
                    "destination_seen_before": False,
                    "transfer_pattern": "staged",
                },
            },
        ]

        for definition in attack_definitions:
            events.append(
                {
                    "event_id": self.next_event_id("ATTACK"),
                    "timestamp": (
                        base_time + timedelta(minutes=definition["minutes"])
                    ).isoformat(),
                    "source_type": definition["source_type"],
                    "event_type": definition["event_type"],
                    "severity": definition["severity"],
                    "organisation_id": "ORG-DEMO-001",
                    "user_id": "USR-104",
                    "username": "anita.sharma",
                    "device_id": "DEV-018",
                    "department": "Examinations",
                    "source_ip": definition["source_ip"],
                    "asset_id": definition["asset_id"],
                    "anomaly_score": definition["anomaly_score"],
                    "confidence": definition["confidence"],
                    "label": "malicious",
                    "scenario_id": "SCN-SILENT-INTRUDER-001",
                    "attack_stage": definition["stage"],
                    "attributes": definition["attributes"],
                    "tags": [
                        "synthetic",
                        "attack",
                        "silent-intruder",
                    ],
                }
            )

        return sorted(events, key=lambda event: event["timestamp"])

    @staticmethod
    def source_for_event(event_type: str) -> str:
        mapping = {
            "login_success": "authentication",
            "logout": "authentication",
            "application_access": "endpoint",
            "file_read": "endpoint",
            "dns_query": "network",
            "internal_connection": "network",
        }

        return mapping.get(event_type, "simulator")

    @staticmethod
    def save_events(
        events: list[dict[str, Any]],
        output_path: Path,
    ) -> None:
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with output_path.open("w", encoding="utf-8") as file:
            json.dump(events, file, indent=2)


def main() -> None:
    simulator = SecurityEventSimulator(random_seed=42)

    normal_events = simulator.generate_normal_events(count=250)
    scenario_events = simulator.generate_silent_intruder()

    combined_events = sorted(
        normal_events + scenario_events,
        key=lambda event: event["timestamp"],
    )

    simulator.save_events(
        normal_events,
        DATASET_DIRECTORY / "normal_events.json",
    )

    simulator.save_events(
        scenario_events,
        DATASET_DIRECTORY / "silent_intruder_events.json",
    )

    simulator.save_events(
        combined_events,
        DATASET_DIRECTORY / "combined_events.json",
    )

    malicious_count = sum(
        event["label"] == "malicious"
        for event in combined_events
    )

    print("CyberShield CNI synthetic dataset generated")
    print(f"Normal events: {len(normal_events)}")
    print(f"Scenario events: {len(scenario_events)}")
    print(f"Malicious events: {malicious_count}")
    print(f"Combined events: {len(combined_events)}")
    print(f"Output directory: {DATASET_DIRECTORY}")


if __name__ == "__main__":
    main()