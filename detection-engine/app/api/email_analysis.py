from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

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