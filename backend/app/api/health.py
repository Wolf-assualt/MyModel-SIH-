from fastapi import APIRouter, Depends
from sqlalchemy import text
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
