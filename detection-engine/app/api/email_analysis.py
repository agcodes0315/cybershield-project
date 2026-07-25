from __future__ import annotations

import sys
from pathlib import Path

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel


PROJECT_ROOT = Path(__file__).resolve().parents[3]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


from services.email_analyzer.app.analyzer import analyze_headers


router = APIRouter()


class EmailRequest(BaseModel):
    raw_headers: str


@router.post("/analyze")
async def analyze_email(req: EmailRequest):
    try:
        return analyze_headers(req.raw_headers)

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Email analysis failed: {str(exc)}",
        ) from exc
