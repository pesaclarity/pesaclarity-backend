"""Liveness and readiness probes."""

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import text

from ngome.api.deps import SessionDep

router = APIRouter(tags=["health"])


class Health(BaseModel):
    status: str


@router.get("/health")
async def health() -> Health:
    return Health(status="ok")


@router.get("/health/ready")
async def ready(session: SessionDep) -> Health:
    try:
        await session.execute(text("SELECT 1"))
    except Exception:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Database unavailable") from None
    return Health(status="ok")
