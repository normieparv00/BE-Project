"""Application configuration management using Pydantic Settings."""

import os
from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Configuration settings loaded from environment variables or .env file."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Ollama Local Service Configuration
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "qwen2.5-coder"
    ollama_timeout_seconds: float = 60.0

    # Static Analysis Executable Paths
    semgrep_path: str = "semgrep"
    bandit_path: str = "bandit"

    # Application & Server Configuration
    log_level: str = "INFO"
    app_host: str = "127.0.0.1"
    app_port: int = 8000


@lru_cache()
def get_settings() -> Settings:
    """Retrieve cached application settings instance."""
    return Settings()
