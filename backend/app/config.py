import os
from typing import Optional

try:
    from pydantic_settings import BaseSettings
except ImportError:
    from pydantic import BaseSettings


class Settings(BaseSettings):
    # API Configuration
    API_V1_STR: str = "/api/v1"
    PROJECT_NAME: str = "SecureGuard Email Scam Detection API"
    VERSION: str = "1.0.0"
    DESCRIPTION: str = "AI-powered email scam detection backend"

    # Server Configuration
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    DEBUG: bool = False

    # Security
    SECRET_KEY: str = "your-secret-key-change-in-production"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # External API Keys
    VIRUSTOTAL_API_KEY: Optional[str] = None
    GOOGLE_SAFE_BROWSING_API_KEY: Optional[str] = None
    GOOGLE_WEB_RISK_API_KEY: Optional[str] = None
    GEMINI_API_KEY: Optional[str] = None
    SOPHOS_AUTH_TOKEN: Optional[str] = None

    # Database Configuration (for future use)
    DATABASE_URL: Optional[str] = None

    # Redis Configuration (for caching)
    REDIS_URL: str = "redis://localhost:6379/0"

    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = 60

    # Analysis Configuration
    MAX_EMAIL_SIZE: int = 10 * 1024 * 1024  # 10MB
    MAX_ATTACHMENT_SIZE: int = 50 * 1024 * 1024  # 50MB
    ANALYSIS_TIMEOUT: int = 30  # seconds

    # Risk Scoring Weights
    HEADER_ANALYSIS_WEIGHT: float = 0.0
    LINK_ANALYSIS_WEIGHT: float = 0.0
    ATTACHMENT_ANALYSIS_WEIGHT: float = 0.20
    CONTENT_ANALYSIS_WEIGHT: float = 0.4

    # Thresholds
    LOW_RISK_THRESHOLD: int = 30
    MEDIUM_RISK_THRESHOLD: int = 60
    HIGH_RISK_THRESHOLD: int = 80

    class Config:
        env_file = ".env"
        case_sensitive = True
        extra = "ignore"  # Ignore extra fields in .env file


# Global settings instance
settings = Settings()


# Environment-specific configurations
def get_settings() -> Settings:
    return settings
