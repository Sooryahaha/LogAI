"""Application configuration using pydantic-settings."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Global application settings loaded from environment variables."""

    APP_NAME: str = "AI Secure Data Intelligence Platform"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False

    # Google Gemini configuration
    GEMINI_API_KEY: str = ""
    GEMINI_MODEL: str = "gemini-2.0-flash"

    # File upload limits
    MAX_FILE_SIZE_MB: int = 10
    MAX_CONTENT_LENGTH: int = 500_000  # characters

    # Log analysis
    LOG_CHUNK_SIZE: int = 5000  # lines per chunk
    MAX_LOG_LINES: int = 100_000

    # Rate limiting
    RATE_LIMIT_REQUESTS: int = 60
    RATE_LIMIT_WINDOW: int = 60  # seconds

    ALLOWED_FILE_EXTENSIONS: list[str] = [".txt", ".log", ".pdf", ".doc", ".docx"]

    model_config = SettingsConfigDict(env_file=".env", case_sensitive=True)


settings = Settings()
