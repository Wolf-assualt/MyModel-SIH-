"""Database schema initialization utility."""
from app.core.config import settings
from app.core.logging import logger, setup_logging
from app.db.base import Base
from app.db.session import engine

# Import all models so that Base.metadata has registered every table
import app.models  # noqa: F401


def init_db() -> None:
    """Create all database tables and ensure directories exist."""
    setup_logging()
    settings.ensure_directories()
    logger.info("Initializing database schemas...")
    Base.metadata.create_all(bind=engine)
    logger.info("Database schemas initialized successfully.")


if __name__ == "__main__":
    init_db()

