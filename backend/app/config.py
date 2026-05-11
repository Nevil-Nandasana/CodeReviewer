"""
Application configuration — all settings loaded from environment variables.
Copy .env.example to .env and fill in values before running.
"""
from __future__ import annotations
from functools import lru_cache
from typing import Literal
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # ── Environment ─────────────────────────────────────────────────────────
    ENVIRONMENT: Literal["development", "staging", "production"] = "development"
    DEBUG: bool = True

    # ── Database ─────────────────────────────────────────────────────────────
    DATABASE_URL: str = "postgresql://cruser:crpassword@localhost:5432/codereviewai"

    # ── Redis ────────────────────────────────────────────────────────────────
    REDIS_URL: str = "redis://localhost:6379/0"

    # ── JWT Auth ─────────────────────────────────────────────────────────────
    JWT_SECRET_KEY: str = "change-me-in-production-32-char-minimum"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 1440  # 24 hours

    # ── CORS ─────────────────────────────────────────────────────────────────
    # Stored as a comma-separated string, not list[str]. pydantic-settings
    # treats a list field as "complex" and runs json.loads on the raw .env value
    # *before* any before-validator gets a chance, so `CORS_ORIGINS=a,b` raises
    # a JSONDecodeError at import time. Same pattern as SUPPORTED_LANGUAGES.
    CORS_ORIGINS: str = "http://localhost:3000,http://localhost:5173"

    # ── Model Backend ─────────────────────────────────────────────────────────
    MODEL_BACKEND: Literal["local", "openai"] = "openai"
    LOCAL_MODEL_PATH: str = "./training/models/deepseek-codereview-6.7b"
    OPENAI_API_KEY: str = ""
    OPENAI_MODEL: str = "gpt-4o-mini"
    MODEL_TEMPERATURE: float = 0.1
    MODEL_MAX_NEW_TOKENS: int = 1024
    REVIEW_CACHE_TTL: int = 3600  # 1 hour Redis cache

    # ── GitHub App ────────────────────────────────────────────────────────────
    GITHUB_APP_ID: str = ""
    GITHUB_APP_PRIVATE_KEY_PATH: str = "./secrets/github-app.private-key.pem"
    GITHUB_WEBHOOK_SECRET: str = "change-me-webhook-secret"
    GITHUB_CLIENT_ID: str = ""
    GITHUB_CLIENT_SECRET: str = ""

    # ── Celery ───────────────────────────────────────────────────────────────
    CELERY_BROKER_URL: str = "redis://localhost:6379/1"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/2"

    # ── Analysis ─────────────────────────────────────────────────────────────
    SUPPORTED_LANGUAGES: str = "python,javascript,typescript,java,go"
    MAX_DIFF_SIZE_KB: int = 500
    MAX_FILES_PER_PR: int = 50

    @property
    def supported_languages_list(self) -> list[str]:
        return [l.strip() for l in self.SUPPORTED_LANGUAGES.split(",") if l.strip()]

    @property
    def cors_origins_list(self) -> list[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]

    class Config:
        env_file = ".env"
        case_sensitive = True
        extra = "ignore"


# Values that must never reach a deployed environment.
INSECURE_DEFAULTS = {
    "JWT_SECRET_KEY": ("change-me", "your-jwt-secret", "CHANGE-ME"),
    "GITHUB_WEBHOOK_SECRET": ("change-me", "your-webhook-secret"),
}


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()


def unknown_env_keys(env_path: str = ".env") -> list[str]:
    """
    Keys present in .env that no Settings field consumes.

    `extra="ignore"` means a typo or a renamed setting is discarded in silence.
    That is how `MAX_FILE_SIZE_KB` came to sit in .env while the code read
    `MAX_DIFF_SIZE_KB`, with the limit never taking effect and nothing said.
    """
    from pathlib import Path

    path = Path(env_path)
    if not path.exists():
        return []
    known = set(Settings.model_fields)
    found = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key = line.split("=", 1)[0].strip()
        if key and key not in known:
            found.append(key)
    return found


def insecure_settings() -> list[str]:
    """Settings still holding a placeholder value."""
    problems = []
    for field, markers in INSECURE_DEFAULTS.items():
        value = str(getattr(settings, field, "") or "")
        if any(marker.lower() in value.lower() for marker in markers) or not value:
            problems.append(field)
    return problems


if __name__ == "__main__":  # python -m app.config
    print(f"environment : {settings.ENVIRONMENT}")
    print(f"model backend: {settings.MODEL_BACKEND}")
    stray = unknown_env_keys()
    print(f"unknown .env keys: {', '.join(stray) if stray else 'none'}")
    weak = insecure_settings()
    print(f"placeholder secrets: {', '.join(weak) if weak else 'none'}")
