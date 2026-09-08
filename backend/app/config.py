from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    database_url: str = "sqlite:///./tea121.db"
    storage_dir: Path = Path("./.tea121-data")
    analyzer_command: str = "tea121"
    analyzer_version: str = "0.1.0"
    analyzer_timeout_seconds: float = 120.0
    max_concurrent_runs: int = 2
    max_upload_bytes: int = 5 * 1024 * 1024
    model_config = SettingsConfigDict(env_file=".env", env_prefix="TEA121_", extra="ignore")

    def ensure_storage(self) -> None:
        self.storage_dir.mkdir(parents=True, exist_ok=True)


settings = Settings()
