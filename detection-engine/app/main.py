"""
CyberShield Detection Engine entry point.
"""

from __future__ import annotations

import importlib
import os
from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware


app = FastAPI(
    title="CyberShield Detection Engine",
    description=(
        "FastAPI detection, analysis, correlation and "
        "incident-response service for CyberShield."
    ),
    version="1.0.0",
)


def get_allowed_origins() -> list[str]:
    default_origins = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "https://mango-pebble-099d8de00.7.azurestaticapps.net",
    ]

    configured_origins = os.getenv(
        "CORS_ORIGINS",
        "",
    ).strip()

    if not configured_origins:
        return default_origins

    additional_origins = [
        origin.strip().rstrip("/")
        for origin in configured_origins.split(",")
        if origin.strip()
    ]

    return list(
        dict.fromkeys(
            [
                *default_origins,
                *additional_origins,
            ]
        )
    )


app.add_middleware(
    CORSMiddleware,
    allow_origins=get_allowed_origins(),
    allow_origin_regex=r"https://.*\.azurestaticapps\.net",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
    max_age=86400,
)


ROUTERS: list[tuple[str, str, list[str]]] = [
    ("app.api.scan", "/api/scan", ["URL Scanner"]),
    (
        "app.api.email_analysis",
        "/api/email",
        ["Email Analysis"],
    ),
    (
        "app.api.threats",
        "/api/threats",
        ["Threat Intelligence"],
    ),
    (
        "app.api.recon",
        "/api/recon",
        ["Reconnaissance"],
    ),
    (
        "app.api.gophish",
        "/api/gophish",
        ["GoPhish"],
    ),
    (
        "app.api.yara_scan",
        "/api/yara",
        ["YARA Scanner"],
    ),
    (
        "app.api.breach",
        "/api/breach",
        ["Breach Analysis"],
    ),
    (
        "app.api.vuln",
        "/api/vuln",
        ["Vulnerability Scanner"],
    ),
    (
        "app.api.reports",
        "/api/reports",
        ["Reports"],
    ),
    (
        "app.api.response_orchestrator",
        "/api/orchestrator",
        ["Response Orchestrator"],
    ),
    (
        "app.api.vulnerability_priority",
        "/api/vuln-priority",
        ["Vulnerability Prioritisation"],
    ),
    (
        "app.api.audit_log",
        "/api/audit",
        ["Audit Integrity"],
    ),
    (
        "app.api.correlation",
        "/api/correlation",
        ["Threat Correlation"],
    ),
    (
        "app.api.attack_graph",
        "/api/attack-graph",
        ["Attack Graph"],
    ),
    (
        "app.api.pipeline",
        "/api/pipeline",
        ["Event Pipeline"],
    ),
    (
        "app.api.prediction",
        "/api/prediction",
        ["Attack Prediction"],
    ),
    (
        "app.api.response",
        "/api/response",
        ["Response Automation"],
    ),
    (
        "app.api.ueba",
        "/api/ueba",
        ["UEBA"],
    ),
    (
        "app.api.pentest",
        "/api/pentest",
        ["Penetration Testing"],
    ),
    (
        "app.api.shodan",
        "/api/shodan",
        ["Shodan"],
    ),
    (
        "app.api.vuln_scan",
        "/api/vuln-scan",
        ["Advanced Vulnerability Scan"],
    ),
]


loaded_routers: list[str] = []
failed_routers: dict[str, str] = {}


def register_router(
    module_name: str,
    prefix: str,
    tags: list[str],
) -> None:
    try:
        module: Any = importlib.import_module(module_name)
        router = getattr(module, "router", None)

        if router is None:
            raise AttributeError(
                f"{module_name} does not export a router."
            )

        app.include_router(
            router,
            prefix=prefix,
            tags=tags,
        )

        loaded_routers.append(prefix)

    except Exception as exc:
        failed_routers[module_name] = (
            f"{type(exc).__name__}: {exc}"
        )

        print(
            "[CyberShield] Router skipped:",
            module_name,
            failed_routers[module_name],
        )


for module_name, prefix, tags in ROUTERS:
    register_router(
        module_name,
        prefix,
        tags,
    )


@app.get("/", tags=["System"])
async def root() -> dict[str, Any]:
    return {
        "service": "CyberShield Detection Engine",
        "status": "running",
        "version": "1.0.0",
        "documentation": "/docs",
    }


@app.get("/health", tags=["System"])
@app.get("/api/health", tags=["System"])
async def health() -> dict[str, Any]:
    return {
        "status": "healthy",
        "service": "detection-engine",
        "loaded_router_count": len(loaded_routers),
        "loaded_routers": loaded_routers,
        "failed_router_count": len(failed_routers),
        "failed_routers": failed_routers,
    }
