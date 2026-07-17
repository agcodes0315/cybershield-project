from __future__ import annotations

from typing import Any, Dict, List, Mapping

from .schemas import (
    MitreMappingResult,
    MitreTactic,
    MitreTechnique,
)


TECHNIQUE_CATALOGUE: Dict[str, MitreTechnique] = {
    "T1566.002": MitreTechnique(
        tactic=MitreTactic.INITIAL_ACCESS,
        technique_id="T1566.002",
        technique_name="Spearphishing Link",
        description=(
            "An adversary sends a malicious link to obtain credentials "
            "or execute attacker-controlled content."
        ),
        recommended_mitigations=[
            "Use secure email gateways",
            "Enable URL rewriting and sandboxing",
            "Provide phishing-awareness training",
        ],
    ),
    "T1078": MitreTechnique(
        tactic=MitreTactic.INITIAL_ACCESS,
        technique_id="T1078",
        technique_name="Valid Accounts",
        description=(
            "An adversary uses legitimate credentials to access systems "
            "and evade identity-based controls."
        ),
        recommended_mitigations=[
            "Require phishing-resistant MFA",
            "Revoke suspicious sessions",
            "Monitor impossible-travel activity",
        ],
    ),
    "T1059.001": MitreTechnique(
        tactic=MitreTactic.EXECUTION,
        technique_id="T1059.001",
        technique_name="PowerShell",
        description=(
            "An adversary uses PowerShell commands for execution, "
            "discovery, or payload delivery."
        ),
        recommended_mitigations=[
            "Enable PowerShell script-block logging",
            "Use constrained language mode",
            "Block unsigned or encoded scripts",
        ],
    ),
    "T1003": MitreTechnique(
        tactic=MitreTactic.CREDENTIAL_ACCESS,
        technique_id="T1003",
        technique_name="OS Credential Dumping",
        description=(
            "An adversary attempts to extract account credentials "
            "from operating-system memory or credential stores."
        ),
        recommended_mitigations=[
            "Enable credential protection",
            "Restrict access to LSASS",
            "Rotate exposed credentials",
        ],
    ),
    "T1046": MitreTechnique(
        tactic=MitreTactic.DISCOVERY,
        technique_id="T1046",
        technique_name="Network Service Discovery",
        description=(
            "An adversary scans systems and ports to identify reachable "
            "services and movement opportunities."
        ),
        recommended_mitigations=[
            "Segment internal networks",
            "Monitor internal scanning activity",
            "Restrict east-west traffic",
        ],
    ),
    "T1021": MitreTechnique(
        tactic=MitreTactic.LATERAL_MOVEMENT,
        technique_id="T1021",
        technique_name="Remote Services",
        description=(
            "An adversary uses services such as RDP, SSH, or SMB "
            "to move between internal systems."
        ),
        recommended_mitigations=[
            "Restrict remote administration",
            "Apply privileged-access controls",
            "Require MFA for remote services",
        ],
    ),
    "T1213": MitreTechnique(
        tactic=MitreTactic.COLLECTION,
        technique_id="T1213",
        technique_name="Data from Information Repositories",
        description=(
            "An adversary accesses databases, repositories, or "
            "information systems containing sensitive records."
        ),
        recommended_mitigations=[
            "Apply least privilege",
            "Monitor bulk data queries",
            "Use database activity monitoring",
        ],
    ),
    "T1041": MitreTechnique(
        tactic=MitreTactic.EXFILTRATION,
        technique_id="T1041",
        technique_name="Exfiltration Over C2 Channel",
        description=(
            "An adversary transfers stolen data through an established "
            "command-and-control or encrypted channel."
        ),
        recommended_mitigations=[
            "Apply egress filtering",
            "Inspect unusual encrypted transfers",
            "Block unknown external destinations",
        ],
    ),
}


EVENT_TECHNIQUE_MAP: Dict[str, List[str]] = {
    "phishing_email_detected": ["T1566.002"],
    "login_success": ["T1078"],
    "process_execution": ["T1059.001"],
    "credential_dumping": ["T1003"],
    "network_service_discovery": ["T1046"],
    "remote_service_connection": ["T1021"],
    "sensitive_database_access": ["T1213"],
    "unusual_data_transfer": ["T1041"],
}


class MitreMappingService:
    def map_event(
        self,
        event: Mapping[str, Any],
    ) -> MitreMappingResult:
        event_id = str(event.get("event_id", "UNKNOWN-EVENT"))
        event_type = str(event.get("event_type", "")).strip().lower()
        attributes = event.get("attributes") or {}

        technique_ids = list(
            EVENT_TECHNIQUE_MAP.get(event_type, [])
        )

        evidence: List[str] = []
        confidence = 0.0

        if event_type == "login_success":
            if attributes.get("impossible_travel"):
                evidence.append("Impossible-travel authentication detected")
                confidence += 0.25

            if attributes.get("new_device"):
                evidence.append("Authentication from a new device")
                confidence += 0.15

            if attributes.get("mfa_used") is False:
                evidence.append("Authentication completed without MFA")
                confidence += 0.15

        elif event_type == "process_execution":
            process_name = str(
                attributes.get("process_name", "")
            ).lower()

            if process_name == "powershell.exe":
                evidence.append("PowerShell process executed")
                confidence += 0.35

            if attributes.get("encoded_command"):
                evidence.append("Encoded command observed")
                confidence += 0.30

        elif event_type == "credential_dumping":
            if attributes.get("target_process") == "lsass.exe":
                evidence.append("LSASS process targeted")
                confidence += 0.40

            if attributes.get("memory_access"):
                evidence.append("Credential-process memory accessed")
                confidence += 0.30

        elif event_type == "network_service_discovery":
            destination_count = int(
                attributes.get("destination_count", 0)
            )

            if destination_count >= 10:
                evidence.append(
                    f"{destination_count} internal destinations contacted"
                )
                confidence += 0.35

        elif event_type == "remote_service_connection":
            if attributes.get("first_time_connection"):
                evidence.append("First-time remote service connection")
                confidence += 0.25

            if attributes.get("service_account_used"):
                evidence.append("Service account used for remote access")
                confidence += 0.25

        elif event_type == "sensitive_database_access":
            if attributes.get("access_outside_role"):
                evidence.append("Database access exceeded assigned role")
                confidence += 0.35

            records_accessed = int(
                attributes.get("records_accessed", 0)
            )

            if records_accessed >= 1000:
                evidence.append(
                    f"Bulk access to {records_accessed} records"
                )
                confidence += 0.30

        elif event_type == "unusual_data_transfer":
            transfer_mb = float(
                attributes.get("data_transfer_mb", 0.0)
            )

            if transfer_mb >= 100:
                evidence.append(
                    f"Unusual outbound transfer of {transfer_mb:.2f} MB"
                )
                confidence += 0.35

            if attributes.get("destination_seen_before") is False:
                evidence.append("Previously unseen destination")
                confidence += 0.20

        elif event_type == "phishing_email_detected":
            failed_controls = [
                name.upper()
                for name in ("spf", "dkim", "dmarc")
                if str(
                    attributes.get(f"{name}_result", "")
                ).lower() == "fail"
            ]

            if failed_controls:
                evidence.append(
                    "Failed email controls: "
                    + ", ".join(failed_controls)
                )
                confidence += 0.35

            if attributes.get("user_clicked"):
                evidence.append("User interacted with phishing content")
                confidence += 0.30

        if technique_ids and not evidence:
            evidence.append(
                f"Event type matched known ATT&CK behaviour: {event_type}"
            )
            confidence = 0.65

        if technique_ids:
            confidence = max(confidence, 0.65)

        techniques = [
            TECHNIQUE_CATALOGUE[technique_id]
            for technique_id in technique_ids
        ]

        return MitreMappingResult(
            event_id=event_id,
            event_type=event_type,
            matched=bool(techniques),
            confidence=round(min(confidence, 0.99), 4),
            techniques=techniques,
            evidence=evidence,
        )

    def map_batch(
        self,
        events: List[Mapping[str, Any]],
    ) -> List[MitreMappingResult]:
        return [
            self.map_event(event)
            for event in events
        ]

    def catalogue(self) -> Dict[str, MitreTechnique]:
        return dict(TECHNIQUE_CATALOGUE)


mitre_mapping_service = MitreMappingService()