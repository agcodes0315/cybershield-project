from __future__ import annotations

import os
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.breach import router as breach_router
from app.api.email_analysis import router as email_router
from app.api.gophish import router as gophish_router
from app.api.recon import router as recon_router
from app.api.reports import router as reports_router
from app.api.scan import router as scan_router
from app.api.threats import router as threats_router
from app.api.ueba import router as ueba_router
from app.api.vuln_scan import router as vuln_router
from app.api.yara_scan import router as yara_router


load_dotenv()


def _allowed_origins() -> list[str]:
    """
    Read comma-separated frontend origins from the environment.

    Local defaults support the Vite frontend during development.
    Production should define CORS_ORIGINS explicitly.
    """
    configured_origins = os.getenv(
        "CORS_ORIGINS",
        "http://localhost:5173,http://127.0.0.1:5173",
    )

    origins = [
        origin.strip()
        for origin in configured_origins.split(",")
        if origin.strip()
    ]

    return origins


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """
    Application startup and shutdown lifecycle.

    Later phases can initialise database pools, Redis connections,
    model loading, and telemetry workers here.
    """
    app.state.service_name = "cybershield-detection-engine"
    app.state.service_version = "2.1.0"
    app.state.environment = os.getenv("APP_ENV", "development")

    yield


app = FastAPI(
    title="CyberShield CNI Detection Engine",
    description=(
        "AI-driven behavioural anomaly detection, threat intelligence, "
        "attack-chain analysis, and cyber-resilience services for "
        "critical national infrastructure."
    ),
    version="2.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins(),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
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
    summary="Detection engine information",
)
def root() -> dict[str, Any]:
    return {
        "service": "CyberShield CNI Detection Engine",
        "version": "2.1.0",
        "status": "running",
        "documentation": "/docs",
        "capabilities": [
            "URL threat detection",
            "Email-header analysis",
            "Threat intelligence",
            "Network reconnaissance",
            "YARA scanning",
            "Breach intelligence",
            "Vulnerability scanning",
            "UEBA behavioural anomaly detection",
        ],
    }


@app.get(
    "/health",
    tags=["System"],
    summary="Service health check",
)
def health() -> dict[str, Any]:
    return {
        "status": "healthy",
        "service": "detection-engine",
        "version": "2.1.0",
        "environment": os.getenv("APP_ENV", "development"),
    }


@app.get(
    "/ready",
    tags=["System"],
    summary="Service readiness check",
)
def readiness() -> dict[str, Any]:
    """
    Kubernetes and cloud-container readiness endpoint.

    Database, Redis, and model readiness checks will be added when those
    production adapters are introduced.
    """
    return {
        "status": "ready",
        "service": "detection-engine",
        "checks": {
            "api": True,
            "ueba_module": True,
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

# The UEBA router already defines prefix="/api/ueba",
# so no second prefix is added here.
app.include_router(ueba_router)