from pathlib import Path
from app.core.config import settings


def test_settings_configuration():
    """Verify that settings are loaded with correct values and types."""
    assert settings.APP_NAME == "TRUST-CV"
    assert settings.APP_VERSION == "1.0.0"
    assert settings.DEBUG is False
    assert settings.SQLITE_URL == "sqlite:///./trust_cv.db"
    assert settings.DATA_DIR == "./data"
    assert settings.LOG_LEVEL == "INFO"
    assert settings.DATABASE_URL == "sqlite:///./trust_cv.db"
