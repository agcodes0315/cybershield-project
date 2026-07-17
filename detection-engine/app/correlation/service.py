from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from threading import RLock
from typing import Any, Deque, Dict, Iterable, List, Mapping, Tuple

from app.mitre.service import MitreMappingService

from .schemas import (
    AttackStage,
    CorrelatedEvidence,
    CorrelatedIncident,
    CorrelationSummary,
    IncidentSeverity,
)


TACTIC_ORDER = {
    "Initial Access": 1,
    "Execution": 2,
    "Persistence": 3,
    "Privilege Escalation": 4,
    "Defense Evasion": 5,
    "Credential Access": 6,
    "Discovery": 7,
    "Lateral Movement": 8,
    "Collection": 9,
    "Command and Control": 10,
    "Exfiltration": 11,
    "Impact": 12,
}


CRITICAL_ASSETS = {
    "IDP-001",
    "EXAM-APP-01",
    "EXAM-DB-01",
    "QUESTION-REPO-01",
}


EVENT_CONTRIBUTIONS = {
    "phishing_email_detected": 0.12,
    "login_success": 0.10,
    "process_execution": 0.14,
    "credential_dumping": 0.20,
    "network_service_discovery": 0.12,
    "remote_service_connection": 0.18,
    "sensitive_database_access": 0.22,
    "unusual_data_transfer": 0.25,
}


class CorrelationService:
    """
    Correlate weak signals into attack incidents.

    DSA usage:
    - Hash maps index events by user/device.
    - Deques hold sliding time windows.
    - Sorting builds ordered ATT&CK progressions.
    """

    def __init__(
        self,
        window_minutes: int = 120,
        minimum_events: int = 3,
    ) -> None:
        if window_minutes <= 0:
            raise ValueError(
                "window_minutes must be greater than zero"
            )

        if minimum_events < 2:
            raise ValueError(
                "minimum_events must be at least two"
            )

        self.window = timedelta(minutes=window_minutes)
        self.minimum_events = minimum_events

        self.mitre = MitreMappingService()

        self._entity_windows: Dict[
            str,
            Deque[Mapping[str, Any]],
        ] = defaultdict(deque)

        self._incidents: Dict[
            str,
            CorrelatedIncident,
        ] = {}

        self._lock = RLock()

    def correlate(
        self,
        events: Iterable[Mapping[str, Any]],
    ) -> Tuple[List[CorrelatedIncident], CorrelationSummary]:
        event_list = sorted(
            list(events),
            key=self._timestamp,
        )

        with self._lock:
            self._entity_windows.clear()
            self._incidents.clear()

            for event in event_list:
                entity_id = self._entity_id(event)
                window = self._entity_windows[entity_id]

                window.append(event)

                self._evict_old_events(
                    window=window,
                    reference_time=self._timestamp(event),
                )

            incidents: List[CorrelatedIncident] = []

            for entity_id, entity_events in (
                self._entity_windows.items()
            ):
                incident = self._build_incident(
                    entity_id,
                    list(entity_events),
                )

                if incident is None:
                    continue

                self._incidents[incident.incident_id] = incident
                incidents.append(incident)

            correlated_events = sum(
                incident.event_count
                for incident in incidents
            )

            summary = CorrelationSummary(
                events_processed=len(event_list),
                incidents_created=len(incidents),
                high_or_critical_incidents=sum(
                    incident.severity
                    in {
                        IncidentSeverity.HIGH,
                        IncidentSeverity.CRITICAL,
                    }
                    for incident in incidents
                ),
                correlated_event_count=correlated_events,
                unmatched_event_count=max(
                    len(event_list) - correlated_events,
                    0,
                ),
            )

            return incidents, summary

    def incidents(self) -> List[CorrelatedIncident]:
        with self._lock:
            return sorted(
                self._incidents.values(),
                key=lambda incident: incident.risk_score,
                reverse=True,
            )

    def get_incident(
        self,
        incident_id: str,
    ) -> CorrelatedIncident | None:
        with self._lock:
            return self._incidents.get(incident_id)

    def clear(self) -> None:
        with self._lock:
            self._entity_windows.clear()
            self._incidents.clear()

    def _build_incident(
        self,
        entity_id: str,
        events: List[Mapping[str, Any]],
    ) -> CorrelatedIncident | None:
        suspicious_events = [
            event
            for event in events
            if self._is_suspicious(event)
        ]

        if len(suspicious_events) < self.minimum_events:
            return None

        evidence: List[CorrelatedEvidence] = []
        stages: List[AttackStage] = []
        techniques_seen = set()
        critical_assets = set()
        rules = set()

        total_contribution = 0.0
        confidence_values: List[float] = []

        for event in suspicious_events:
            mapping = self.mitre.map_event(event)

            event_type = str(
                event.get("event_type", "")
            ).lower()

            anomaly_score = self._anomaly_score(event)
            base_contribution = EVENT_CONTRIBUTIONS.get(
                event_type,
                0.08,
            )

            contribution = min(
                base_contribution
                * (0.75 + anomaly_score),
                0.30,
            )

            total_contribution += contribution
            confidence_values.append(
                max(
                    mapping.confidence,
                    float(event.get("confidence", 0.0)),
                )
            )

            asset_id = str(event.get("asset_id") or "")

            if asset_id in CRITICAL_ASSETS:
                critical_assets.add(asset_id)

            evidence.append(
                CorrelatedEvidence(
                    event_id=str(
                        event.get(
                            "event_id",
                            "UNKNOWN-EVENT",
                        )
                    ),
                    timestamp=self._timestamp(event),
                    event_type=event_type,
                    source_type=str(
                        event.get(
                            "source_type",
                            "unknown",
                        )
                    ),
                    entity_id=entity_id,
                    asset_id=asset_id or None,
                    anomaly_score=anomaly_score,
                    contribution=round(
                        contribution,
                        4,
                    ),
                    description=self._describe_event(
                        event
                    ),
                    mitre_techniques=mapping.techniques,
                )
            )

            for technique in mapping.techniques:
                unique_key = (
                    technique.technique_id,
                    str(event.get("event_id")),
                )

                if unique_key in techniques_seen:
                    continue

                techniques_seen.add(unique_key)

                stages.append(
                    AttackStage(
                        order=TACTIC_ORDER.get(
                            technique.tactic.value,
                            99,
                        ),
                        tactic=technique.tactic.value,
                        technique_id=technique.technique_id,
                        technique_name=technique.technique_name,
                        event_id=str(
                            event.get(
                                "event_id",
                                "UNKNOWN-EVENT",
                            )
                        ),
                        timestamp=self._timestamp(event),
                        confidence=mapping.confidence,
                    )
                )

        stages.sort(
            key=lambda stage: (
                stage.timestamp,
                stage.order,
            )
        )

        unique_tactics = {
            stage.tactic
            for stage in stages
        }

        if len(unique_tactics) >= 3:
            rules.add("MULTI_STAGE_ATTACK")

        event_types = {
            str(event.get("event_type", "")).lower()
            for event in suspicious_events
        }

        if {
            "login_success",
            "process_execution",
            "credential_dumping",
        }.issubset(event_types):
            rules.add("COMPROMISED_ACCOUNT_CHAIN")

        if {
            "network_service_discovery",
            "remote_service_connection",
        }.issubset(event_types):
            rules.add("LATERAL_MOVEMENT_CHAIN")

        if {
            "sensitive_database_access",
            "unusual_data_transfer",
        }.issubset(event_types):
            rules.add("DATA_EXFILTRATION_CHAIN")

        if critical_assets:
            rules.add("CRITICAL_ASSET_EXPOSURE")

        stage_bonus = min(
            len(unique_tactics) * 0.04,
            0.24,
        )

        critical_asset_bonus = min(
            len(critical_assets) * 0.05,
            0.15,
        )

        temporal_bonus = (
            0.08
            if len(suspicious_events) >= 5
            else 0.03
        )

        risk_score = min(
            total_contribution
            + stage_bonus
            + critical_asset_bonus
            + temporal_bonus,
            1.0,
        )

        confidence = (
            sum(confidence_values)
            / len(confidence_values)
            if confidence_values
            else 0.0
        )

        severity = self._severity(risk_score)

        probable_next_tactic = self._predict_next_tactic(
            stages
        )

        return CorrelatedIncident(
            title=self._incident_title(
                rules,
                entity_id,
            ),
            summary=self._incident_summary(
                entity_id=entity_id,
                event_count=len(suspicious_events),
                stage_count=len(unique_tactics),
                critical_assets=sorted(
                    critical_assets
                ),
            ),
            organisation_id=str(
                suspicious_events[0].get(
                    "organisation_id",
                    "ORG-DEMO-001",
                )
            ),
            primary_entity_id=entity_id,
            severity=severity,
            risk_score=round(risk_score, 4),
            confidence=round(confidence, 4),
            first_seen=min(
                self._timestamp(event)
                for event in suspicious_events
            ),
            last_seen=max(
                self._timestamp(event)
                for event in suspicious_events
            ),
            event_count=len(suspicious_events),
            unique_asset_count=len(
                {
                    str(event.get("asset_id"))
                    for event in suspicious_events
                    if event.get("asset_id")
                }
            ),
            stage_count=len(unique_tactics),
            evidence=evidence,
            attack_stages=stages,
            probable_next_tactic=probable_next_tactic,
            critical_assets_at_risk=sorted(
                critical_assets
            ),
            recommended_actions=self._recommended_actions(
                event_types,
                critical_assets,
            ),
            correlation_rules=sorted(rules),
        )

    @staticmethod
    def _entity_id(
        event: Mapping[str, Any],
    ) -> str:
        return str(
            event.get("user_id")
            or event.get("device_id")
            or event.get("source_ip")
            or "UNKNOWN-ENTITY"
        )

    @staticmethod
    def _timestamp(
        event: Mapping[str, Any],
    ) -> datetime:
        value = event.get("timestamp")

        if isinstance(value, datetime):
            if value.tzinfo is None:
                return value.replace(
                    tzinfo=timezone.utc
                )

            return value.astimezone(timezone.utc)

        if isinstance(value, str):
            cleaned = value.replace(
                "Z",
                "+00:00",
            )

            parsed = datetime.fromisoformat(
                cleaned
            )

            if parsed.tzinfo is None:
                parsed = parsed.replace(
                    tzinfo=timezone.utc
                )

            return parsed.astimezone(timezone.utc)

        return datetime.now(timezone.utc)

    @staticmethod
    def _anomaly_score(
        event: Mapping[str, Any],
    ) -> float:
        try:
            return min(
                max(
                    float(
                        event.get(
                            "ueba_score",
                            event.get(
                                "anomaly_score",
                                0.0,
                            ),
                        )
                    ),
                    0.0,
                ),
                1.0,
            )
        except (TypeError, ValueError):
            return 0.0

    def _is_suspicious(
        self,
        event: Mapping[str, Any],
    ) -> bool:
        event_type = str(
            event.get("event_type", "")
        ).lower()

        return (
            self._anomaly_score(event) >= 0.50
            or event_type in EVENT_CONTRIBUTIONS
            and str(
                event.get("label", "")
            ).lower() == "malicious"
        )

    def _evict_old_events(
        self,
        window: Deque[Mapping[str, Any]],
        reference_time: datetime,
    ) -> None:
        threshold = reference_time - self.window

        while window:
            oldest = window[0]

            if self._timestamp(oldest) >= threshold:
                break

            window.popleft()

    @staticmethod
    def _severity(
        score: float,
    ) -> IncidentSeverity:
        if score >= 0.85:
            return IncidentSeverity.CRITICAL

        if score >= 0.65:
            return IncidentSeverity.HIGH

        if score >= 0.40:
            return IncidentSeverity.MEDIUM

        return IncidentSeverity.LOW

    @staticmethod
    def _predict_next_tactic(
        stages: List[AttackStage],
    ) -> str | None:
        if not stages:
            return None

        latest_order = max(
            stage.order
            for stage in stages
        )

        ordered_tactics = sorted(
            TACTIC_ORDER.items(),
            key=lambda item: item[1],
        )

        for tactic, order in ordered_tactics:
            if order > latest_order:
                return tactic

        return "Impact"

    @staticmethod
    def _describe_event(
        event: Mapping[str, Any],
    ) -> str:
        event_type = str(
            event.get("event_type", "unknown")
        ).replace("_", " ")

        asset = event.get("asset_id")
        user = event.get("user_id")

        description = event_type.title()

        if user:
            description += f" associated with {user}"

        if asset:
            description += f" targeting {asset}"

        return description

    @staticmethod
    def _incident_title(
        rules: set[str],
        entity_id: str,
    ) -> str:
        if "DATA_EXFILTRATION_CHAIN" in rules:
            return (
                f"Probable data-exfiltration campaign involving "
                f"{entity_id}"
            )

        if "LATERAL_MOVEMENT_CHAIN" in rules:
            return (
                f"Probable lateral movement involving "
                f"{entity_id}"
            )

        if "COMPROMISED_ACCOUNT_CHAIN" in rules:
            return (
                f"Probable compromised account: "
                f"{entity_id}"
            )

        return (
            f"Correlated suspicious activity for "
            f"{entity_id}"
        )

    @staticmethod
    def _incident_summary(
        entity_id: str,
        event_count: int,
        stage_count: int,
        critical_assets: List[str],
    ) -> str:
        summary = (
            f"CyberShield correlated {event_count} suspicious events "
            f"for {entity_id} across {stage_count} ATT&CK tactics."
        )

        if critical_assets:
            summary += (
                " Critical assets at risk: "
                + ", ".join(critical_assets)
                + "."
            )

        return summary

    @staticmethod
    def _recommended_actions(
        event_types: set[str],
        critical_assets: set[str],
    ) -> List[str]:
        actions = [
            "Open a high-priority SOC investigation",
            "Preserve endpoint and authentication evidence",
        ]

        if "login_success" in event_types:
            actions.append(
                "Revoke active sessions and require credential reset"
            )

        if (
            "process_execution" in event_types
            or "credential_dumping" in event_types
        ):
            actions.append(
                "Isolate the affected endpoint after analyst approval"
            )

        if "remote_service_connection" in event_types:
            actions.append(
                "Block unauthorised east-west remote access"
            )

        if critical_assets:
            actions.append(
                "Restrict access to exposed critical assets"
            )

        if "unusual_data_transfer" in event_types:
            actions.append(
                "Block the suspicious outbound destination"
            )

        return actions


correlation_service = CorrelationService()