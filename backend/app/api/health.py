from pathlib import Path
from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.crypto.signer import default_signer
from app.graph.engine import default_graph_engine
from app.schemas.base import ResponseEnvelope

router = APIRouter(prefix="/system", tags=["System"])


@router.get("/health", response_model=ResponseEnvelope[dict])
def health_check() -> ResponseEnvelope[dict]:
    """Basic liveness and operational health probe."""
    return ResponseEnvelope(
        data={
            "status": "healthy",
            "app": settings.APP_NAME,
            "version": settings.APP_VERSION,
            "air_gapped_mode": True,
        }
    )


@router.get("/status", response_model=ResponseEnvelope[dict])
def status_check(db: Session = Depends(get_db)) -> ResponseEnvelope[dict]:
    """Database connectivity and runtime telemetry probe."""
    result = db.execute(text("PRAGMA journal_mode")).scalar()
    return ResponseEnvelope(
        data={
            "database": "connected",
            "journal_mode": str(result).upper(),
            "sqlite_url": settings.SQLITE_URL,
            "status": "operational",
        }
    )


@router.get("/readiness", response_model=ResponseEnvelope[dict])
def readiness_check(db: Session = Depends(get_db)) -> ResponseEnvelope[dict]:
    """Deep readiness probe verifying all individual assurance subsystems."""
    # 1. Database check
    db_ok = False
    journal_mode = "UNKNOWN"
    try:
        journal_mode = str(db.execute(text("PRAGMA journal_mode")).scalar()).upper()
        db_ok = True
    except Exception:
        db_ok = False

    # 2. Crypto subsystem check
    crypto_ok = False
    pub_pem = None
    try:
        pub_pem = default_signer.export_public_key_pem()
        if isinstance(pub_pem, bytes):
            crypto_ok = bool(pub_pem and b"PUBLIC KEY" in pub_pem)
        else:
            crypto_ok = bool(pub_pem and "PUBLIC KEY" in str(pub_pem))
    except Exception:
        crypto_ok = False

    # 3. Storage directory check
    storage_ok = False
    try:
        data_dir = Path(settings.DATA_DIR).resolve()
        data_dir.mkdir(parents=True, exist_ok=True)
        test_file = data_dir / ".health_check_tmp"
        test_file.write_text("ok", encoding="utf-8")
        test_file.unlink(missing_ok=True)
        storage_ok = True
    except Exception:
        storage_ok = False

    # 4. Graph subsystem check
    graph_ok = default_graph_engine is not None

    # 5. Static assets check
    static_dir = Path(__file__).resolve().parent.parent / "static"
    index_html = Path(__file__).resolve().parent.parent / "templates" / "index.html"
    assets_ok = static_dir.exists() and index_html.exists()

    all_ready = all([db_ok, crypto_ok, storage_ok, graph_ok, assets_ok])

    return ResponseEnvelope(
        data={
            "ready": all_ready,
            "subsystems": {
                "database": {"status": "HEALTHY" if db_ok else "DEGRADED", "journal_mode": journal_mode},
                "cryptography": {"status": "HEALTHY" if crypto_ok else "DEGRADED", "algorithm": "ECDSA_SECP256R1"},
                "storage": {"status": "HEALTHY" if storage_ok else "DEGRADED", "path": str(settings.DATA_DIR)},
                "graph_engine": {"status": "HEALTHY" if graph_ok else "DEGRADED", "nodes": len(default_graph_engine.nodes)},
                "dashboard_assets": {"status": "HEALTHY" if assets_ok else "DEGRADED", "mode": "AIR_GAPPED_LOCAL"},
            },
            "environment": {
                "debug": settings.DEBUG,
                "version": settings.APP_VERSION,
                "log_level": settings.LOG_LEVEL,
            }
        }
    )
