"""
Pytest Configuration and Fixtures

This file contains shared fixtures used across all tests.
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime

from fastapi.testclient import TestClient
from httpx import AsyncClient, ASGITransport

from app.models.schemas import (
    SessionData,
    ExtractedIntelligence,
    HoneypotRequest,
    Message,
    Metadata
)


@pytest.fixture(scope="session")
def event_loop():
    """Create an event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def mock_settings():
    """Mock settings for testing."""
    with patch("app.config.settings") as mock:
        mock.API_KEY = "test-api-key"
        mock.GEMINI_API_KEY = "test-gemini-key"
        mock.GEMINI_MODEL = "gemini-1.5-flash"
        mock.SESSION_TTL_SECONDS = 3600
        mock.MAX_INACTIVE_SECONDS = 300
        mock.CALLBACK_URL = "https://test-callback.example.com"
        mock.LOG_LEVEL = "DEBUG"
        yield mock


@pytest.fixture
def sample_session_data():
    """Create a sample session for testing."""
    return SessionData(
        session_id="test-session-123",
        created_at=datetime.utcnow(),
        last_activity=datetime.utcnow(),
        conversation_history=[],
        total_messages=0,
        scam_detected=False,
        scam_confidence=0.0,
        scam_type=None,
        extracted_intelligence=ExtractedIntelligence(),
        agent_notes=[],
        conversation_ended=False,
        callback_sent=False,
        channel="SMS",
        language="English"
    )


@pytest.fixture
def sample_honeypot_request():
    """Create a sample honeypot request."""
    return HoneypotRequest(
        sessionId="test-session-123",
        message=Message(
            sender="scammer",
            text="You have won a lottery of 10 lakh rupees! Send your OTP to claim.",
            timestamp=1700000000000
        ),
        conversationHistory=[],
        metadata=Metadata(
            channel="SMS",
            language="English",
            locale="IN"
        )
    )


@pytest.fixture
def sample_scam_messages():
    """Collection of scam messages for testing."""
    return [
        "Congratulations! You won 10 lakh lottery. Share OTP to claim prize.",
        "Your bank account will be blocked within 24 hours. Share OTP immediately.",
        "KYC update required. Click here: http://fake-bank.example.com",
        "Send payment to UPI: scammer@ybl to receive your refund",
        "Your card ending 1234 is blocked. Call 9876543210 urgently.",
        "You received 5 crore from government scheme. Pay processing fee of 5000",
    ]


@pytest.fixture
def sample_legitimate_messages():
    """Collection of non-scam messages for testing."""
    return [
        "Hello, how are you?",
        "Can you help me with my order?",
        "What time does your store close?",
        "Thank you for your help yesterday.",
        "I'm looking for information about your services.",
    ]


@pytest.fixture
def mock_gemini_client():
    """Mock the Gemini client for testing without API calls."""
    with patch("app.core.gemini_client.gemini_client") as mock:
        mock.analyze_for_scam = AsyncMock(return_value={
            "confidence": 0.85,
            "scam_type": "lottery_scam",
            "indicators": ["lottery", "prize", "otp"]
        })
        mock.extract_intelligence = AsyncMock(return_value={
            "upi_ids": [],
            "phone_numbers": [],
            "bank_accounts": [],
            "urls": []
        })
        mock.generate_response = AsyncMock(return_value=(
            "Achha beta, 10 lakh! Bade paise hain... kaise milenge?",
            "Engaging scammer to gather more intel"
        ))
        yield mock


@pytest.fixture
def extracted_intelligence_sample():
    """Sample extracted intelligence."""
    return ExtractedIntelligence(
        bankAccounts=["123456789012"],
        upiIds=["scammer@ybl", "fraud@paytm"],
        phishingLinks=["http://fake-bank.example.com"],
        phoneNumbers=["9876543210"],
        suspiciousKeywords=["lottery", "otp", "urgent"]
    )
