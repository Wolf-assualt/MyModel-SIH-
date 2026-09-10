from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    APP_NAME: str = "TRUST-CV"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    SQLITE_URL: str = "sqlite:///./trust_cv.db"
    DATA_DIR: str = "./data"
    LOG_LEVEL: str = "INFO"

    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore",
    )

    @property
    def DATABASE_URL(self) -> str:
        return self.SQLITE_URL


settings = Settings()
