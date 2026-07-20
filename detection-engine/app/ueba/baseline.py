from __future__ import annotations

import statistics
from collections import defaultdict
from datetime import datetime, timezone
from threading import RLock
from typing import Any, Dict, Iterable, List, Mapping, Optional, Set

from .schemas import AnomalyReason, BehaviourProfile


def _attributes(event: Mapping[str, Any]) -> Mapping[str, Any]:
    value = event.get("attributes")
    return value if isinstance(value, Mapping) else {}


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


class BehaviourBaselineService:
    """
    Builds per-user behavioural profiles.

    DSA:
    - Hash maps provide O(1)-average profile lookup.
    - Sets prevent duplicate devices, IPs, assets and processes.
    """

    def __init__(self) -> None:
        self._profiles: Dict[str, BehaviourProfile] = {}
        self._lock = RLock()

    def fit(
        self,
        events: Iterable[Mapping[str, Any]],
    ) -> Dict[str, BehaviourProfile]:
        grouped: Dict[str, List[Mapping[str, Any]]] = defaultdict(list)

        for event in events:
            entity_id = str(
                event.get("user_id")
                or event.get("device_id")
                or "UNKNOWN-ENTITY"
            )
            grouped[entity_id].append(event)

        profiles: Dict[str, BehaviourProfile] = {}

        for entity_id, entity_events in grouped.items():
            profiles[entity_id] = self._build_profile(
                entity_id,
                entity_events,
            )

        with self._lock:
            self._profiles = profiles

        return dict(profiles)

    def get_profile(
        self,
        entity_id: str,
    ) -> Optional[BehaviourProfile]:
        with self._lock:
            return self._profiles.get(entity_id)

    def all_profiles(self) -> Dict[str, BehaviourProfile]:
        with self._lock:
            return dict(self._profiles)

    def count(self) -> int:
        with self._lock:
            return len(self._profiles)

    def clear(self) -> None:
        with self._lock:
            self._profiles.clear()

    def explain_deviation(
        self,
        event: Mapping[str, Any],
        profile: BehaviourProfile,
    ) -> List[AnomalyReason]:
        attributes = _attributes(event)
        reasons: List[AnomalyReason] = []

        login_hour = _safe_float(
            attributes.get("login_hour"),
            12.0,
        )

        login_deviation = self._z_score(
            login_hour,
            profile.mean_login_hour,
            profile.std_login_hour,
        )

        if login_hour < 7 or login_hour > 21:
            reasons.append(
                AnomalyReason(
                    code="OFF_HOURS_LOGIN",
                    description="Login occurred outside the user's normal working hours.",
                    contribution=0.18,
                    observed_value=f"{login_hour:.0f}:00",
                    expected_value=(
                        f"around {profile.mean_login_hour:.1f}:00"
                    ),
                )
            )
        elif login_deviation >= 2.0:
            reasons.append(
                AnomalyReason(
                    code="LOGIN_TIME_DEVIATION",
                    description="Login time significantly deviates from the user's baseline.",
                    contribution=min(login_deviation / 10.0, 0.15),
                    observed_value=f"{login_hour:.1f}",
                    expected_value=f"{profile.mean_login_hour:.1f}",
                )
            )

        device_id = str(event.get("device_id") or "")

        if device_id and device_id not in profile.known_devices:
            reasons.append(
                AnomalyReason(
                    code="NEW_DEVICE",
                    description="The event originated from a device not previously associated with this user.",
                    contribution=0.18,
                    observed_value=device_id,
                    expected_value=", ".join(profile.known_devices[:3]),
                )
            )

        source_ip = str(event.get("source_ip") or "")

        if source_ip and source_ip not in profile.known_source_ips:
            reasons.append(
                AnomalyReason(
                    code="NEW_SOURCE_IP",
                    description="The source IP is not part of the user's established baseline.",
                    contribution=0.12,
                    observed_value=source_ip,
                    expected_value=", ".join(profile.known_source_ips[:3]),
                )
            )

        asset_id = str(event.get("asset_id") or "")

        if asset_id and asset_id not in profile.known_assets:
            reasons.append(
                AnomalyReason(
                    code="UNUSUAL_ASSET_ACCESS",
                    description="The user accessed an asset not present in their historical baseline.",
                    contribution=0.15,
                    observed_value=asset_id,
                    expected_value=", ".join(profile.known_assets[:4]),
                )
            )

        failed_logins = _safe_float(
            attributes.get("failed_login_count")
        )

        failed_deviation = self._z_score(
            failed_logins,
            profile.mean_failed_logins,
            profile.std_failed_logins,
        )

        if failed_logins >= 5 or failed_deviation >= 3.0:
            reasons.append(
                AnomalyReason(
                    code="FAILED_LOGIN_SPIKE",
                    description="Failed authentication attempts exceed the normal user baseline.",
                    contribution=0.16,
                    observed_value=str(int(failed_logins)),
                    expected_value=f"{profile.mean_failed_logins:.2f}",
                )
            )

        transfer_mb = _safe_float(
            attributes.get("data_transfer_mb")
        )

        transfer_deviation = self._z_score(
            transfer_mb,
            profile.mean_data_transfer_mb,
            profile.std_data_transfer_mb,
        )

        if transfer_mb >= 250 or transfer_deviation >= 4.0:
            reasons.append(
                AnomalyReason(
                    code="DATA_TRANSFER_SPIKE",
                    description="Data transfer volume significantly exceeds the user's normal activity.",
                    contribution=0.20,
                    observed_value=f"{transfer_mb:.2f} MB",
                    expected_value=(
                        f"{profile.mean_data_transfer_mb:.2f} MB"
                    ),
                )
            )

        process_name = str(
            attributes.get("process_name") or ""
        ).lower()

        if (
            process_name
            and profile.known_processes
            and process_name not in profile.known_processes
        ):
            reasons.append(
                AnomalyReason(
                    code="RARE_PROCESS",
                    description="The executed process has not appeared in the user's normal baseline.",
                    contribution=0.16,
                    observed_value=process_name,
                    expected_value=", ".join(profile.known_processes[:4]),
                )
            )

        if attributes.get("encoded_command"):
            reasons.append(
                AnomalyReason(
                    code="ENCODED_COMMAND",
                    description="An encoded command was observed during process execution.",
                    contribution=0.22,
                    observed_value="true",
                    expected_value="false",
                )
            )

        if attributes.get("impossible_travel"):
            reasons.append(
                AnomalyReason(
                    code="IMPOSSIBLE_TRAVEL",
                    description="Authentication locations imply physically impossible travel.",
                    contribution=0.22,
                    observed_value="true",
                    expected_value="false",
                )
            )

        if attributes.get("privilege_escalation_observed"):
            reasons.append(
                AnomalyReason(
                    code="PRIVILEGE_ESCALATION",
                    description="Privilege escalation behaviour was observed.",
                    contribution=0.25,
                    observed_value="true",
                    expected_value="false",
                )
            )

        return reasons

    @staticmethod
    def _z_score(
        value: float,
        mean: float,
        standard_deviation: float,
    ) -> float:
        if standard_deviation <= 0.000001:
            return 0.0 if abs(value - mean) < 0.000001 else 5.0

        return abs(value - mean) / standard_deviation

    def _build_profile(
        self,
        entity_id: str,
        events: List[Mapping[str, Any]],
    ) -> BehaviourProfile:
        login_hours: List[float] = []
        data_transfers: List[float] = []
        failed_logins: List[float] = []

        devices: Set[str] = set()
        source_ips: Set[str] = set()
        assets: Set[str] = set()
        event_types: Set[str] = set()
        processes: Set[str] = set()

        for event in events:
            attributes = _attributes(event)

            login_hours.append(
                _safe_float(attributes.get("login_hour"), 12.0)
            )
            data_transfers.append(
                _safe_float(attributes.get("data_transfer_mb"))
            )
            failed_logins.append(
                _safe_float(attributes.get("failed_login_count"))
            )

            if event.get("device_id"):
                devices.add(str(event["device_id"]))

            if event.get("source_ip"):
                source_ips.add(str(event["source_ip"]))

            if event.get("asset_id"):
                assets.add(str(event["asset_id"]))

            if event.get("event_type"):
                event_types.add(str(event["event_type"]))

            process_name = attributes.get("process_name")

            if process_name:
                processes.add(str(process_name).lower())

        return BehaviourProfile(
            entity_id=entity_id,
            event_count=len(events),
            mean_login_hour=self._mean(login_hours),
            std_login_hour=self._std(login_hours),
            mean_data_transfer_mb=self._mean(data_transfers),
            std_data_transfer_mb=self._std(data_transfers),
            mean_failed_logins=self._mean(failed_logins),
            std_failed_logins=self._std(failed_logins),
            known_devices=sorted(devices),
            known_source_ips=sorted(source_ips),
            known_assets=sorted(assets),
            known_event_types=sorted(event_types),
            known_processes=sorted(processes),
            updated_at=datetime.now(timezone.utc),
        )

    @staticmethod
    def _mean(values: List[float]) -> float:
        return statistics.fmean(values) if values else 0.0

    @staticmethod
    def _std(values: List[float]) -> float:
        return statistics.pstdev(values) if len(values) > 1 else 0.0