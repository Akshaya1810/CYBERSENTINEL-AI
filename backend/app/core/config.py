from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "CyberSentinel AI API"
    environment: str = "development"
    database_url: str = "postgresql+psycopg://postgres:CHANGE_ME@localhost:5432/cybersentinel"
    ssh_bruteforce_threshold: int = Field(default=4, gt=0)
    ssh_bruteforce_window_seconds: int = Field(default=300, gt=0)
    ssh_bruteforce_exempt_usernames: str = ""
    ssh_success_failure_threshold: int = Field(default=5, gt=0)
    ssh_success_failure_window_seconds: int = Field(default=600, gt=0)
    ssh_invalid_user_threshold: int = Field(default=3, gt=0)
    ssh_invalid_user_window_seconds: int = Field(default=300, gt=0)
    detection_grouping_window_seconds: int = Field(default=1800, gt=0)
    ollama_api_url: str = "http://127.0.0.1:11434/api/chat"
    ollama_model: str = "qwen2.5:3b"
    ollama_timeout_seconds: float = Field(default=300, gt=0, le=300)

    model_config = SettingsConfigDict(
        env_file=Path(__file__).resolve().parents[2] / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()
