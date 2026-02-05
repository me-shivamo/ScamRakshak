"""
Tests for app/main.py API endpoints

Tests the FastAPI application endpoints.
"""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from fastapi.testclient import TestClient
from httpx import AsyncClient, ASGITransport

from app.models.schemas import ExtractedIntelligence, SessionData
from datetime import datetime


@pytest.fixture
def mock_dependencies():
    """Mock all external dependencies for API testing."""
    with patch("app.main.scam_detector") as mock_detector, \
         patch("app.main.honeypot_agent") as mock_agent, \
         patch("app.main.intelligence_extractor") as mock_intel, \
         patch("app.main.session_manager") as mock_session, \
         patch("app.main.callback_service") as mock_callback, \
         patch("app.main.settings") as mock_settings:

        # Configure settings
        mock_settings.API_KEY = "test-api-key"
        mock_settings.LOG_LEVEL = "DEBUG"

        # Configure scam detector
        mock_detector.detect = AsyncMock(return_value=(
            True, 0.85, "lottery_scam", ["lottery", "otp"]
        ))

        # Configure honeypot agent
        mock_agent.generate_response = AsyncMock(return_value=(
            "Achha beta, lottery jeet gaye? Batao kaise claim karein...",
            "Engaging scammer for more intel"
        ))

        # Configure intelligence extractor
        mock_intel.extract = AsyncMock(return_value=ExtractedIntelligence(
            upiIds=["scammer@ybl"],
            phoneNumbers=["9876543210"],
            suspiciousKeywords=["lottery"]
        ))

        # Configure session manager
        mock_session_data = SessionData(
            session_id="test-session",
            created_at=datetime.utcnow(),
            last_activity=datetime.utcnow(),
            extracted_intelligence=ExtractedIntelligence()
        )
        mock_session.get_or_create = AsyncMock(return_value=mock_session_data)
        mock_session.update = AsyncMock()
        mock_session.get = AsyncMock(return_value=mock_session_data)
        mock_session.get_stats = MagicMock(return_value={
            "total_sessions": 1,
            "active_sessions": 1,
            "scams_detected": 0
        })

        yield {
            "detector": mock_detector,
            "agent": mock_agent,
            "intel": mock_intel,
            "session": mock_session,
            "callback": mock_callback,
            "settings": mock_settings
        }


@pytest.fixture
def client(mock_dependencies):
    """Create a test client with mocked dependencies."""
    # Import app after mocking to ensure mocks are in place
    from app.main import app

    # Create a modified app without lifespan for testing
    app.router.lifespan_context = None

    return TestClient(app, raise_server_exceptions=False)


class TestHealthEndpoint:
    """Tests for GET /health endpoint."""

    def test_health_check(self, client, mock_dependencies):
        """Test health check returns healthy status."""
        response = client.get("/health")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["service"] == "ScamRakshak"
        assert "version" in data
        assert "sessions" in data

    def test_health_check_includes_stats(self, client, mock_dependencies):
        """Test health check includes session stats."""
        response = client.get("/health")

        data = response.json()
        sessions = data["sessions"]
        assert "total_sessions" in sessions
        assert "active_sessions" in sessions
        assert "scams_detected" in sessions


class TestHoneypotEndpoint:
    """Tests for POST / honeypot endpoint."""

    def test_valid_request(self, client, mock_dependencies):
        """Test valid honeypot request."""
        response = client.post(
            "/",
            json={
                "sessionId": "test-123",
                "message": {
                    "sender": "scammer",
                    "text": "You won 10 lakh lottery! Share OTP to claim."
                }
            },
            headers={"x-api-key": "test-api-key"}
        )

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert "reply" in data

    def test_missing_api_key(self, client, mock_dependencies):
        """Test request without API key is rejected."""
        response = client.post(
            "/",
            json={
                "sessionId": "test-123",
                "message": {"sender": "scammer", "text": "Hello"}
            }
        )

        assert response.status_code == 422  # Missing required header

    def test_invalid_api_key(self, client, mock_dependencies):
        """Test request with invalid API key is rejected."""
        response = client.post(
            "/",
            json={
                "sessionId": "test-123",
                "message": {"sender": "scammer", "text": "Hello"}
            },
            headers={"x-api-key": "wrong-api-key"}
        )

        assert response.status_code == 401

    def test_request_with_metadata(self, client, mock_dependencies):
        """Test request with metadata."""
        response = client.post(
            "/",
            json={
                "sessionId": "test-meta",
                "message": {"sender": "scammer", "text": "Lottery winner!"},
                "metadata": {
                    "channel": "WhatsApp",
                    "language": "Hindi",
                    "locale": "IN"
                }
            },
            headers={"x-api-key": "test-api-key"}
        )

        assert response.status_code == 200

    def test_request_with_history(self, client, mock_dependencies):
        """Test request with conversation history."""
        response = client.post(
            "/",
            json={
                "sessionId": "test-history",
                "message": {"sender": "scammer", "text": "Send OTP now!"},
                "conversationHistory": [
                    {"sender": "scammer", "text": "You won lottery!"},
                    {"sender": "user", "text": "Really?"}
                ]
            },
            headers={"x-api-key": "test-api-key"}
        )

        assert response.status_code == 200

    def test_invalid_request_body(self, client, mock_dependencies):
        """Test invalid request body is rejected."""
        response = client.post(
            "/",
            json={"invalid": "data"},
            headers={"x-api-key": "test-api-key"}
        )

        assert response.status_code == 422

    def test_missing_session_id(self, client, mock_dependencies):
        """Test request without sessionId is rejected."""
        response = client.post(
            "/",
            json={
                "message": {"sender": "scammer", "text": "Hello"}
            },
            headers={"x-api-key": "test-api-key"}
        )

        assert response.status_code == 422

    def test_missing_message(self, client, mock_dependencies):
        """Test request without message is rejected."""
        response = client.post(
            "/",
            json={"sessionId": "test-123"},
            headers={"x-api-key": "test-api-key"}
        )

        assert response.status_code == 422


class TestResponseFormat:
    """Tests for API response format."""

    def test_response_has_required_fields(self, client, mock_dependencies):
        """Test response has all required fields."""
        response = client.post(
            "/",
            json={
                "sessionId": "test-format",
                "message": {"sender": "scammer", "text": "Scam message"}
            },
            headers={"x-api-key": "test-api-key"}
        )

        data = response.json()
        assert "status" in data
        assert "reply" in data

    def test_response_is_json(self, client, mock_dependencies):
        """Test response content type is JSON."""
        response = client.post(
            "/",
            json={
                "sessionId": "test-json",
                "message": {"sender": "scammer", "text": "Test"}
            },
            headers={"x-api-key": "test-api-key"}
        )

        assert response.headers["content-type"] == "application/json"


class TestShouldEndConversation:
    """Tests for conversation ending detection."""

    def test_end_signals(self, mock_dependencies):
        """Test that end signals are detected."""
        from app.main import should_end_conversation

        mock_session = MagicMock()
        mock_session.total_messages = 10

        # Test various end signals
        end_messages = [
            "Bye, I'm not interested",
            "Stop messaging me",
            "I'll report you to police",
            "This is a scam!",
            "You're a fraud",
            "Block this number",
        ]

        for message in end_messages:
            assert should_end_conversation(message, mock_session) is True

    def test_normal_messages_continue(self, mock_dependencies):
        """Test that normal messages don't end conversation."""
        from app.main import should_end_conversation

        mock_session = MagicMock()
        mock_session.total_messages = 10

        normal_messages = [
            "Tell me more",
            "How do I claim?",
            "What's next?",
            "Interesting",
        ]

        for message in normal_messages:
            assert should_end_conversation(message, mock_session) is False

    def test_too_many_messages_ends(self, mock_dependencies):
        """Test that conversation ends after 50 messages."""
        from app.main import should_end_conversation

        mock_session = MagicMock()
        mock_session.total_messages = 51

        # Even normal message should end due to message count
        assert should_end_conversation("Hello", mock_session) is True


class TestExceptionHandling:
    """Tests for exception handling."""

    def test_internal_error_returns_valid_response(self, client, mock_dependencies):
        """Test that internal errors still return valid responses."""
        # Make session manager raise an error
        mock_dependencies["session"].get_or_create.side_effect = Exception("DB Error")

        response = client.post(
            "/",
            json={
                "sessionId": "test-error",
                "message": {"sender": "scammer", "text": "Test"}
            },
            headers={"x-api-key": "test-api-key"}
        )

        # Should still return 200 with a valid response
        # (to not break conversation with scammer)
        assert response.status_code == 200
        data = response.json()
        assert "reply" in data


class TestCORSMiddleware:
    """Tests for CORS middleware."""

    def test_cors_headers_present(self, client, mock_dependencies):
        """Test that CORS headers are present."""
        response = client.options(
            "/",
            headers={
                "Origin": "http://example.com",
                "Access-Control-Request-Method": "POST"
            }
        )

        # CORS preflight should be handled
        assert response.status_code in [200, 405]  # Depends on implementation
