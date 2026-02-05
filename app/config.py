"""
Configuration Management for ScamRakshak

This file reads environment variables and makes them available to the app.
Think of it like a settings panel - all configuration in one place.

HOW IT WORKS:
1. When the app starts, this file reads from .env file (or system environment)
2. It validates that required values exist (API_KEY, OPENAI_API_KEY)
3. It provides default values for optional settings
4. Other files import 'settings' from here to access configuration
"""

import os
from functools import lru_cache
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables.

    Pydantic automatically:
    - Reads from .env file
    - Converts types (str to int, etc.)
    - Raises errors if required fields are missing
    """

    # ===== Required Settings (app won't start without these) =====

    # Your secret API key - GUVI tester sends this in x-api-key header
    API_KEY: str

    # OpenAI API key for AI capabilities
    OPENAI_API_KEY: str

    # ===== Optional Settings (have default values) =====

    # Which OpenAI model to use
    # gpt-4o-mini = fast and cheap, good for hackathons
    # gpt-4o = more powerful but slower and more expensive
    OPENAI_MODEL: str = "gpt-4o-mini"


    # Session timeout in seconds (default: 1 hour)
    # After this time, old sessions are cleaned up
    SESSION_TTL_SECONDS: int = 3600

    # Inactivity timeout in seconds (default: 5 minutes)
    # If no message for this long, we consider conversation ended
    MAX_INACTIVE_SECONDS: int = 300

    # GUVI callback URL (where we send final results)
    GUVI_CALLBACK_URL: str = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"

    # Logging level (DEBUG, INFO, WARNING, ERROR)
    LOG_LEVEL: str = "INFO"

    class Config:
        # Tell Pydantic to read from .env file
        env_file = ".env"
        # Environment variable names are case-sensitive
        case_sensitive = True


# This decorator caches the settings so we don't read .env file repeatedly
@lru_cache()
def get_settings() -> Settings:
    """
    Get application settings (cached for performance).

    lru_cache means: "Remember the result after first call"
    So if we call get_settings() 100 times, it only reads .env once.
    """
    return Settings()


# Create a global settings object that other files can import
# Usage in other files: from app.config import settings
settings = get_settings()
