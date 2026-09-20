"""Ledger-specific database configuration."""
from typing import Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session

from app.core.config import settings

ledger_engine = create_engine(
    settings.LEDGER_SQLITE_URL,
    connect_args={"check_same_thread": False},
)

LedgerSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=ledger_engine)

LedgerBase = declarative_base()


def get_ledger_db() -> Generator[Session, None, None]:
    """Get a ledger database session."""
    db = LedgerSessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()