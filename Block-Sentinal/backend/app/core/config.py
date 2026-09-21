# pyrefly: ignore [missing-import]
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    APP_NAME: str = "TRUST-CV"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    SQLITE_URL: str = "sqlite:///./trust_cv.db"
    LEDGER_SQLITE_URL: str = "sqlite:///./data/ledger/ledger.db"
    DATA_DIR: str = "./data"
    LOG_LEVEL: str = "INFO"
    MAX_UPLOAD_FILES: int = 3000

    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore",
    )

    @property
    def DATABASE_URL(self) -> str:
        return self.SQLITE_URL

    @property
    def REQUIRED_SUBDIRS(self) -> list[str]:
        return [
            "manifests",
            "models",
            "inference_dna",
            "fingerprints",
            "drift",
            "graph",
            "reports/assurance",
            "quarantine/attacks",
            "fusion/assessments",
        ]

    def ensure_directories(self) -> list:
        """Ensure all required local air-gapped storage directories exist idempotently."""
        from pathlib import Path

        base_path = Path(self.DATA_DIR).resolve()
        base_path.mkdir(parents=True, exist_ok=True)
        created_paths = [base_path]

        for subdir in self.REQUIRED_SUBDIRS:
            target_path = base_path / subdir
            target_path.mkdir(parents=True, exist_ok=True)
            created_paths.append(target_path)

        return created_paths


settings = Settings()
