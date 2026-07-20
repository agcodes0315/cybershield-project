from __future__ import annotations

import json
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[2]

OUTPUT_PATH = (
    PROJECT_ROOT
    / "event-simulator"
    / "datasets"
    / "infrastructure_topology.json"
)


def build_topology() -> dict[str, Any]:
    return {
        "topology_id": "TOPO-CNI-EXAM-001",
        "organisation_id": "ORG-DEMO-001",
        "name": (
            "Government Examination "
            "Infrastructure Topology"
        ),
        "nodes": [
            {
                "node_id": "USR-104",
                "name": "Anita Sharma",
                "node_type": "user",
                "criticality": "medium",
                "zone": "Examinations Department",
                "owner": "Examinations",
                "exposure_score": 0.45,
                "vulnerability_score": 0.35,
                "business_impact_score": 0.40,
                "compromised": True,
                "metadata": {
                    "department": "Examinations"
                },
            },
            {
                "node_id": "DEV-018",
                "name": (
                    "Examination Officer "
                    "Workstation"
                ),
                "node_type": "workstation",
                "criticality": "high",
                "ip_address": "10.0.1.18",
                "zone": "User Network",
                "owner": "Examinations",
                "exposure_score": 0.65,
                "vulnerability_score": 0.60,
                "business_impact_score": 0.60,
                "compromised": True,
            },
            {
                "node_id": "IDP-001",
                "name": "Identity Provider",
                "node_type": "identity_provider",
                "criticality": "critical",
                "ip_address": "10.0.2.10",
                "zone": "Identity Zone",
                "owner": "IT Security",
                "exposure_score": 0.45,
                "vulnerability_score": 0.40,
                "business_impact_score": 0.95,
            },
            {
                "node_id": "PORTAL-001",
                "name": "Public Examination Portal",
                "node_type": "application",
                "criticality": "high",
                "ip_address": "10.0.2.20",
                "zone": "DMZ",
                "owner": "Digital Services",
                "exposure_score": 0.90,
                "vulnerability_score": 0.55,
                "business_impact_score": 0.80,
            },
            {
                "node_id": "EXAM-APP-01",
                "name": (
                    "Examination Management "
                    "Application"
                ),
                "node_type": "application",
                "criticality": "critical",
                "ip_address": "10.0.3.20",
                "zone": "Application Zone",
                "owner": "Examinations",
                "exposure_score": 0.45,
                "vulnerability_score": 0.62,
                "business_impact_score": 0.95,
            },
            {
                "node_id": "EXAM-DB-01",
                "name": (
                    "Examination Records "
                    "Database"
                ),
                "node_type": "database",
                "criticality": "critical",
                "ip_address": "10.0.4.30",
                "zone": "Data Zone",
                "owner": "Examinations",
                "exposure_score": 0.25,
                "vulnerability_score": 0.52,
                "business_impact_score": 1.00,
            },
            {
                "node_id": "QUESTION-REPO-01",
                "name": "Question Paper Repository",
                "node_type": "storage",
                "criticality": "critical",
                "ip_address": "10.0.4.40",
                "zone": "Restricted Data Zone",
                "owner": "Examinations",
                "exposure_score": 0.15,
                "vulnerability_score": 0.35,
                "business_impact_score": 1.00,
            },
            {
                "node_id": "BACKUP-01",
                "name": "Examination Backup Server",
                "node_type": "backup",
                "criticality": "high",
                "ip_address": "10.0.5.20",
                "zone": "Backup Zone",
                "owner": "Infrastructure",
                "exposure_score": 0.20,
                "vulnerability_score": 0.45,
                "business_impact_score": 0.85,
            },
            {
                "node_id": "SOC-001",
                "name": "Security Monitoring System",
                "node_type": "security_system",
                "criticality": "critical",
                "ip_address": "10.0.6.10",
                "zone": "Security Zone",
                "owner": "SOC",
                "exposure_score": 0.20,
                "vulnerability_score": 0.25,
                "business_impact_score": 0.90,
            },
        ],
        "edges": [
            {
                "source_id": "USR-104",
                "target_id": "DEV-018",
                "connection_type": "administers",
                "resistance": 0.15,
                "trust_level": 0.95,
                "controls": [
                    "Endpoint authentication"
                ],
            },
            {
                "source_id": "DEV-018",
                "target_id": "IDP-001",
                "connection_type": "authenticates_to",
                "resistance": 0.30,
                "trust_level": 0.85,
                "controls": [
                    "Password authentication",
                    "Conditional access",
                ],
            },
            {
                "source_id": "DEV-018",
                "target_id": "PORTAL-001",
                "connection_type": "connects_to",
                "resistance": 0.40,
                "trust_level": 0.65,
                "controls": [
                    "TLS",
                    "Web application firewall",
                ],
            },
            {
                "source_id": "IDP-001",
                "target_id": "EXAM-APP-01",
                "connection_type": "trusts",
                "resistance": 0.30,
                "trust_level": 0.90,
                "controls": [
                    "Single sign-on",
                    "Role-based access control",
                ],
            },
            {
                "source_id": "PORTAL-001",
                "target_id": "EXAM-APP-01",
                "connection_type": "connects_to",
                "resistance": 0.45,
                "trust_level": 0.70,
                "controls": [
                    "API authentication",
                    "Network segmentation",
                ],
            },
            {
                "source_id": "DEV-018",
                "target_id": "EXAM-APP-01",
                "connection_type": "remote_access",
                "resistance": 0.35,
                "trust_level": 0.65,
                "controls": [
                    "RDP restriction",
                    "Endpoint firewall",
                ],
            },
            {
                "source_id": "EXAM-APP-01",
                "target_id": "EXAM-DB-01",
                "connection_type": "reads_from",
                "resistance": 0.25,
                "trust_level": 0.95,
                "controls": [
                    "Database credentials",
                    "Service-account permissions",
                ],
            },
            {
                "source_id": "EXAM-APP-01",
                "target_id": "QUESTION-REPO-01",
                "connection_type": "reads_from",
                "resistance": 0.40,
                "trust_level": 0.80,
                "controls": [
                    "Application allow-list",
                    "Repository permissions",
                ],
            },
            {
                "source_id": "EXAM-DB-01",
                "target_id": "BACKUP-01",
                "connection_type": "backs_up",
                "resistance": 0.35,
                "trust_level": 0.85,
                "controls": [
                    "Backup service account",
                    "Restricted backup network",
                ],
            },
            {
                "source_id": "QUESTION-REPO-01",
                "target_id": "BACKUP-01",
                "connection_type": "backs_up",
                "resistance": 0.38,
                "trust_level": 0.82,
                "controls": [
                    "Encrypted backup channel",
                    "Repository backup role",
                ],
            },
            {
                "source_id": "SOC-001",
                "target_id": "DEV-018",
                "connection_type": "monitors",
                "resistance": 0.80,
                "trust_level": 0.75,
                "controls": [
                    "EDR telemetry"
                ],
            },
            {
                "source_id": "SOC-001",
                "target_id": "EXAM-APP-01",
                "connection_type": "monitors",
                "resistance": 0.80,
                "trust_level": 0.75,
                "controls": [
                    "Application monitoring"
                ],
            },
            {
                "source_id": "SOC-001",
                "target_id": "EXAM-DB-01",
                "connection_type": "monitors",
                "resistance": 0.80,
                "trust_level": 0.75,
                "controls": [
                    "Database audit logging"
                ],
            },
        ],
        "metadata": {
            "scenario": "Silent Intruder",
            "synthetic": True,
            "description": (
                "Synthetic topology used for attack-path, "
                "blast-radius, and resilience simulation."
            ),
        },
    }


def save_topology(
    output_path: Path = OUTPUT_PATH,
) -> Path:
    topology = build_topology()

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with output_path.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            topology,
            file,
            indent=2,
        )

    return output_path


def main() -> None:
    output_path = save_topology()
    topology = build_topology()

    print(
        "CyberShield infrastructure topology generated"
    )
    print(
        f"Nodes: {len(topology['nodes'])}"
    )
    print(
        f"Edges: {len(topology['edges'])}"
    )
    print(
        f"Output: {output_path}"
    )


if __name__ == "__main__":
    main()