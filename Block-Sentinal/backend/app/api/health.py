# pyrefly: ignore [missing-import]
from fastapi import APIRouter, Depends
# pyrefly: ignore [missing-import]
from sqlalchemy import text
# pyrefly: ignore [missing-import]
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.schemas.base import ResponseEnvelope

router = APIRouter(prefix="/system", tags=["System"])


@router.get("/health", response_model=ResponseEnvelope[dict])
def health_check() -> ResponseEnvelope[dict]:
    return ResponseEnvelope(
        data={
            "status": "healthy",
            "app": settings.APP_NAME,
            "version": settings.APP_VERSION,
        }
    )


@router.get("/status", response_model=ResponseEnvelope[dict])
def status_check(db: Session = Depends(get_db)) -> ResponseEnvelope[dict]:
    db.execute(text("SELECT 1"))
    return ResponseEnvelope(
        data={
            "database": "connected",
            "sqlite_url": settings.SQLITE_URL,
            "status": "operational",
        }
    )


@router.get("/readiness", response_model=ResponseEnvelope[dict])
def readiness_check(db: Session = Depends(get_db)) -> ResponseEnvelope[dict]:
    """Offline system readiness and operational state inspection."""
    db.execute(text("SELECT 1"))
    return ResponseEnvelope(
        data={
            "ready": True,
            "status": "healthy",
            "database": "connected",
            "airgap": True,
            "crypto": "ECDSA_SECP256R1",
            "app": settings.APP_NAME,
            "version": settings.APP_VERSION,
        }
    )

