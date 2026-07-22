from __future__ import annotations

import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware


# ---------------------------------------------------------------------------
# Import-path configuration
#
# app/main.py is located at:
#   project-root/detection-engine/app/main.py
#
# Some existing CyberShield modules import sibling services using:
#   from services....
#
# Therefore, both the detection-engine directory and the project root must be
# available on sys.path before those modules are imported.
# ---------------------------------------------------------------------------

APP_DIRECTORY = Path(__file__).resolve().parent
DETECTION_ENGINE_DIRECTORY = APP_DIRECTORY.parent
PROJECT_ROOT_DIRECTORY = DETECTION_ENGINE_DIRECTORY.parent

for directory in (
    DETECTION_ENGINE_DIRECTORY,
    PROJECT_ROOT_DIRECTORY,
):
    directory_string = str(directory)

    if directory_string not in sys.path:
        sys.path.insert(0, directory_string)


from app.api.attack_graph import router as attack_graph_router
from app.api.audit_log import router as audit_log_router
from app.api.breach import router as breach_router
from app.api.correlation import router as correlation_router
from app.api.email_analysis import router as email_router
from app.api.gophish import router as gophish_router
from app.api.pipeline import router as pipeline_router
from app.api.prediction import router as prediction_router
from app.api.recon import router as recon_router
from app.api.reports import router as reports_router
from app.api.response import router as response_router
from app.api.response_orchestrator import (
    router as response_orchestrator_router,
)
from app.api.scan import router as scan_router
from app.api.threats import router as threats_router
from app.api.ueba import router as ueba_router
from app.api.vuln_scan import router as vuln_router
from app.api.vulnerability_priority import (
    router as vulnerability_priority_router,
)
from app.api.yara_scan import router as yara_router


load_dotenv()


SERVICE_NAME = "cybershield-detection-engine"
SERVICE_DISPLAY_NAME = "CyberShield CNI Detection Engine"
SERVICE_VERSION = "4.1.1"


def get_allowed_origins() -> list[str]:
    configured_origins = os.getenv(
        "CORS_ORIGINS",
        (
            "http://localhost:5173,"
            "http://127.0.0.1:5173,"
            "https://mango-pebble-099d8de00.7.azurestaticapps.net"
        ),
    )

    return [
        origin.strip()
        for origin in configured_origins.split(",")
        if origin.strip()
    ]


@asynccontextmanager
async def lifespan(
    app: FastAPI,
) -> AsyncIterator[None]:
    app.state.service_name = SERVICE_NAME
    app.state.service_version = SERVICE_VERSION
    app.state.environment = os.getenv(
        "APP_ENV",
        "development",
    )

    yield


app = FastAPI(
    title=SERVICE_DISPLAY_NAME,
    description=(
        "AI-driven cyber-resilience platform for critical national "
        "infrastructure with UEBA, weak-signal correlation, attack-path "
        "analysis, response planning, vulnerability prioritisation, "
        "human-gated simulated containment, and tamper-evident auditing."
    ),
    version=SERVICE_VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=get_allowed_origins(),
    allow_credentials=True,
    allow_methods=[
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "OPTIONS",
    ],
    allow_headers=[
        "Authorization",
        "Content-Type",
        "Accept",
        "Origin",
        "X-Requested-With",
    ],
)


@app.get(
    "/",
    tags=["System"],
)
def root() -> dict[str, Any]:
    return {
        "service": SERVICE_DISPLAY_NAME,
        "service_id": SERVICE_NAME,
        "version": SERVICE_VERSION,
        "status": "running",
        "environment": os.getenv(
            "APP_ENV",
            "development",
        ),
        "documentation": "/docs",
        "simulation_only_response": True,
        "paths": {
            "application_directory": str(APP_DIRECTORY),
            "detection_engine_directory": str(
                DETECTION_ENGINE_DIRECTORY
            ),
            "project_root_directory": str(
                PROJECT_ROOT_DIRECTORY
            ),
        },
        "capabilities": [
            "phishing and malicious URL analysis",
            "email threat analysis",
            "YARA scanning",
            "network reconnaissance",
            "breach intelligence",
            "vulnerability scanning",
            "UEBA anomaly detection",
            "weak-signal correlation",
            "attack-path modelling",
            "attack-stage prediction",
            "response playbooks",
            "human approval workflows",
            "safe simulated containment",
            "vulnerability prioritisation",
            "SHA-256 chained audit trail",
            "end-to-end resilience pipeline",
        ],
        "prototype_disclosures": {
            "response_execution": (
                "Simulation mode only. No live infrastructure is modified."
            ),
            "audit_storage": (
                "Currently in-memory for demonstration unless PostgreSQL "
                "persistence has been configured separately."
            ),
            "vulnerability_demo_data": (
                "The demonstration endpoint uses synthetic findings."
            ),
        },
    }


@app.get(
    "/health",
    tags=["System"],
)
def health() -> dict[str, Any]:
    return {
        "status": "healthy",
        "service": SERVICE_NAME,
        "version": SERVICE_VERSION,
        "environment": os.getenv(
            "APP_ENV",
            "development",
        ),
    }


@app.get(
    "/ready",
    tags=["System"],
)
def readiness() -> dict[str, Any]:
    return {
        "status": "ready",
        "service": SERVICE_NAME,
        "version": SERVICE_VERSION,
        "checks": {
            "api": True,
            "phishing_detection": True,
            "email_analysis": True,
            "yara_scanning": True,
            "reconnaissance": True,
            "breach_intelligence": True,
            "vulnerability_scanning": True,
            "ueba": True,
            "correlation": True,
            "prediction": True,
            "attack_graph": True,
            "response_playbooks": True,
            "approval_engine": True,
            "safe_executor": True,
            "vulnerability_prioritisation": True,
            "audit_integrity": True,
            "resilience_pipeline": True,
        },
        "execution_modes": {
            "response_orchestrator": "SIMULATED",
            "audit_storage": "IN_MEMORY_DEMO",
        },
    }


# ---------------------------------------------------------------------------
# Existing CyberShield detection and intelligence routes
# ---------------------------------------------------------------------------

app.include_router(
    scan_router,
    prefix="/api/scan",
    tags=["URL and Threat Scanning"],
)

app.include_router(
    email_router,
    prefix="/api/email",
    tags=["Email Analysis"],
)

app.include_router(
    threats_router,
    prefix="/api/threats",
    tags=["Threat Intelligence"],
)

app.include_router(
    reports_router,
    prefix="/api/reports",
    tags=["Reports"],
)

app.include_router(
    recon_router,
    prefix="/api/recon",
    tags=["Reconnaissance"],
)

app.include_router(
    gophish_router,
    prefix="/api/gophish",
    tags=["GoPhish"],
)

app.include_router(
    yara_router,
    prefix="/api/yara",
    tags=["YARA Analysis"],
)

app.include_router(
    breach_router,
    prefix="/api/breach",
    tags=["Breach Intelligence"],
)

app.include_router(
    vuln_router,
    prefix="/api/vuln",
    tags=["Vulnerability Scanner"],
)


# ---------------------------------------------------------------------------
# Existing CNI resilience and AI routes
# ---------------------------------------------------------------------------

app.include_router(
    ueba_router,
)

app.include_router(
    correlation_router,
)

app.include_router(
    attack_graph_router,
)

app.include_router(
    prediction_router,
)

app.include_router(
    response_router,
)

app.include_router(
    pipeline_router,
)


# ---------------------------------------------------------------------------
# New PS7-aligned prototype additions
# ---------------------------------------------------------------------------

app.include_router(
    vulnerability_priority_router,
    prefix="/api/vuln-priority",
    tags=["Vulnerability Prioritisation"],
)

app.include_router(
    audit_log_router,
    prefix="/api/audit",
    tags=["Audit Integrity"],
)

app.include_router(
    response_orchestrator_router,
    prefix="/api/orchestrator",
    tags=["Simulated Response Orchestrator"],
)