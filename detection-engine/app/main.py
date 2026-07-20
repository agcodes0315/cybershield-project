from __future__ import annotations

import os
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import (
    CORSMiddleware,
)

from app.api.attack_graph import (
    router as attack_graph_router,
)
from app.api.breach import (
    router as breach_router,
)
from app.api.correlation import (
    router as correlation_router,
)
from app.api.email_analysis import (
    router as email_router,
)
from app.api.gophish import (
    router as gophish_router,
)
from app.api.pipeline import (
    router as pipeline_router,
)
from app.api.prediction import (
    router as prediction_router,
)
from app.api.recon import (
    router as recon_router,
)
from app.api.reports import (
    router as reports_router,
)
from app.api.response import (
    router as response_router,
)
from app.api.scan import (
    router as scan_router,
)
from app.api.threats import (
    router as threats_router,
)
from app.api.ueba import (
    router as ueba_router,
)
from app.api.vuln_scan import (
    router as vuln_router,
)
from app.api.yara_scan import (
    router as yara_router,
)


load_dotenv()


def get_allowed_origins() -> list[str]:
    configured_origins = os.getenv(
        "CORS_ORIGINS",
        (
            "http://localhost:5173,"
            "http://127.0.0.1:5173"
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
    app.state.service_name = (
        "cybershield-detection-engine"
    )
    app.state.service_version = "4.0.0"
    app.state.environment = os.getenv(
        "APP_ENV",
        "development",
    )

    yield


app = FastAPI(
    title="CyberShield CNI Detection Engine",
    description=(
        "AI-driven cyber-resilience platform for critical "
        "national infrastructure with UEBA, MITRE ATT&CK "
        "correlation, attack prediction, graph intelligence, "
        "human-gated SOAR response, and tamper-evident audit."
    ),
    version="4.0.0",
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
        "service": (
            "CyberShield CNI Detection Engine"
        ),
        "version": "4.0.0",
        "status": "running",
        "documentation": "/docs",
        "simulation_only_response": True,
        "capabilities": [
            "UEBA anomaly detection",
            "MITRE ATT&CK mapping",
            "weak-signal correlation",
            "Viterbi attack prediction",
            "attack-path modelling",
            "blast-radius calculation",
            "remediation prioritisation",
            "human-gated SOAR response",
            "single and dual approvals",
            "safe response simulation",
            "SHA-256 chained audit ledger",
            "end-to-end resilience pipeline",
        ],
    }


@app.get(
    "/health",
    tags=["System"],
)
def health() -> dict[str, Any]:
    return {
        "status": "healthy",
        "service": "detection-engine",
        "version": "4.0.0",
    }


@app.get(
    "/ready",
    tags=["System"],
)
def readiness() -> dict[str, Any]:
    return {
        "status": "ready",
        "checks": {
            "api": True,
            "ueba": True,
            "mitre": True,
            "correlation": True,
            "prediction": True,
            "attack_graph": True,
            "remediation": True,
            "response_playbooks": True,
            "approval_engine": True,
            "safe_executor": True,
            "audit_ledger": True,
            "resilience_pipeline": True,
        },
    }


app.include_router(
    scan_router,
    prefix="/api/scan",
)

app.include_router(
    email_router,
    prefix="/api/email",
)

app.include_router(
    threats_router,
    prefix="/api/threats",
)

app.include_router(
    reports_router,
    prefix="/api/reports",
)

app.include_router(
    recon_router,
    prefix="/api/recon",
)

app.include_router(
    gophish_router,
    prefix="/api/gophish",
)

app.include_router(
    yara_router,
    prefix="/api/yara",
)

app.include_router(
    breach_router,
    prefix="/api/breach",
)

app.include_router(
    vuln_router,
    prefix="/api/vuln",
)

app.include_router(ueba_router)
app.include_router(correlation_router)
app.include_router(attack_graph_router)
app.include_router(prediction_router)
app.include_router(response_router)
app.include_router(pipeline_router)