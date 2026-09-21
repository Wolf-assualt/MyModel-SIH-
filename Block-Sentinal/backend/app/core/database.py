from typing import Generator
from sqlalchemy import create_engine, event
from sqlalchemy.orm import declarative_base, sessionmaker, Session

from app.core.config import settings

engine = create_engine(
    settings.SQLITE_URL,
    connect_args={"check_same_thread": False},
)

@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA journal_mode=WAL;")
    cursor.close()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
        db.commit()
    finally:
        db.close()


def init_db() -> None:
    """Create all database tables and ensure directories exist."""
    from app.core.logging import logger
    settings.ensure_directories()
    logger.info("Initializing database schemas...")
    import app.models  # noqa: F401
    Base.metadata.create_all(bind=engine)
    logger.info("Database schemas initialized successfully.")


__all__ = ["engine", "SessionLocal", "Base", "get_db", "init_db"]
