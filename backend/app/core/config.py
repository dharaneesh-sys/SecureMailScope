"""Application configuration (environment driven, no secrets in source)."""

from __future__ import annotations

from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_DIR = Path(__file__).resolve().parents[2]
ROOT_DIR = BACKEND_DIR.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SMS_", env_file=BACKEND_DIR / ".env", extra="ignore")

    data_dir: Path = Field(default=BACKEND_DIR / "data")
    reports_dir: Path | None = None
    demo_dir: Path = Field(default=ROOT_DIR / "sample_data" / "authorised_demo_captures")
    database_url: str | None = None

    tshark_path: str | None = None  # None -> discover on PATH
    max_upload_mb: int = 50
    analysis_timeout_s: int = 120
    max_packets: int = 2_000_000
    retention_days: int = 30
    retain_original_captures: bool = True
    cors_origins: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]

    # Optional AI layer. Default "none": built-in deterministic explanations only.
    ai_provider: str = "none"  # none | ollama | openai_compatible
    ai_endpoint: str = "http://localhost:11434"
    ai_model: str = "llama3.1"
    ai_api_key: str | None = None

    @property
    def uploads_dir(self) -> Path:
        return self.data_dir / "uploads"

    @property
    def reports_path(self) -> Path:
        return self.reports_dir or (self.data_dir / "reports")

    @property
    def db_url(self) -> str:
        return self.database_url or f"sqlite:///{self.data_dir / 'securemailscope.db'}"

    def ensure_dirs(self) -> None:
        for d in (self.data_dir, self.uploads_dir, self.reports_path):
            d.mkdir(parents=True, exist_ok=True)


settings = Settings()
