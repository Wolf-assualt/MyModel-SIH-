"""System health and operational readiness endpoint."""
from datetime import datetime, timezone
from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.session import get_db

router = APIRouter()


@router.get("/health", summary="Check system health, offline integrity, and database readiness")
def get_health(db: Session = Depends(get_db)):
    """Operational health check confirming air-gapped readiness and database connectivity."""
    db_connected = False
    try:
        db.execute(text("SELECT 1"))
        db_connected = True
    except Exception:
        db_connected = False

    storage_ready = (
        settings.DATA_DIR.exists() and
        settings.MODELS_DIR.exists() and
        settings.REPORTS_DIR.exists()
    )

    return {
        "status": "healthy" if db_connected else "degraded",
        "project": settings.PROJECT_NAME,
        "full_name": settings.PROJECT_FULL_NAME,
        "version": settings.VERSION,
        "offline_mode": settings.OFFLINE_MODE,
        "air_gapped_enforced": not settings.ALLOW_EXTERNAL_CALLS,
        "database_connected": db_connected,
        "storage_ready": storage_ready,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
