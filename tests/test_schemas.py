"""
Tests for app/models/schemas.py

Tests Pydantic schemas and data validation.
"""

import pytest
from datetime import datetime
from pydantic import ValidationError
from app.models.schemas import (
    Message,
    ConversationMessage,
    Metadata,
    HoneypotRequest,
    HoneypotResponse,
    ExtractedIntelligence,
    CallbackPayload,
    SessionData
)


class TestMessage:
    """Tests for Message schema."""

    def test_valid_message(self):
        """Test creating a valid message."""
        msg = Message(
            sender="scammer",
            text="You won lottery!",
            timestamp=1700000000000
        )
        assert msg.sender == "scammer"
        assert msg.text == "You won lottery!"
        assert msg.timestamp == 1700000000000

    def test_message_without_timestamp(self):
        """Test message with optional timestamp omitted."""
        msg = Message(sender="user", text="Hello")
        assert msg.timestamp is None

    def test_message_requires_sender(self):
        """Test that sender is required."""
        with pytest.raises(ValidationError):
            Message(text="Hello")

    def test_message_requires_text(self):
        """Test that text is required."""
        with pytest.raises(ValidationError):
            Message(sender="user")


class TestConversationMessage:
    """Tests for ConversationMessage schema."""

    def test_valid_conversation_message(self):
        """Test creating a valid conversation message."""
        msg = ConversationMessage(
            sender="agent",
            text="Tell me more",
            timestamp=1700000000000
        )
        assert msg.sender == "agent"
        assert msg.text == "Tell me more"


class TestMetadata:
    """Tests for Metadata schema."""

    def test_full_metadata(self):
        """Test metadata with all fields."""
        meta = Metadata(
            channel="WhatsApp",
            language="Hindi",
            locale="IN"
        )
        assert meta.channel == "WhatsApp"
        assert meta.language == "Hindi"
        assert meta.locale == "IN"

    def test_default_metadata(self):
        """Test metadata with default values."""
        meta = Metadata()
        assert meta.channel is None
        assert meta.language == "English"
        assert meta.locale == "IN"

    def test_partial_metadata(self):
        """Test metadata with partial values."""
        meta = Metadata(channel="SMS")
        assert meta.channel == "SMS"
        assert meta.language == "English"


class TestHoneypotRequest:
    """Tests for HoneypotRequest schema."""

    def test_valid_request(self):
        """Test creating a valid honeypot request."""
        req = HoneypotRequest(
            sessionId="test-123",
            message=Message(sender="scammer", text="Scam message"),
            conversationHistory=[],
            metadata=Metadata(channel="SMS")
        )
        assert req.sessionId == "test-123"
        assert req.message.text == "Scam message"

    def test_minimal_request(self):
        """Test request with only required fields."""
        req = HoneypotRequest(
            sessionId="test-456",
            message=Message(sender="scammer", text="Hello")
        )
        assert req.sessionId == "test-456"
        assert req.conversationHistory == []
        assert req.metadata is None

    def test_request_requires_session_id(self):
        """Test that sessionId is required."""
        with pytest.raises(ValidationError):
            HoneypotRequest(
                message=Message(sender="scammer", text="Hello")
            )

    def test_request_requires_message(self):
        """Test that message is required."""
        with pytest.raises(ValidationError):
            HoneypotRequest(sessionId="test-789")

    def test_request_with_history(self):
        """Test request with conversation history."""
        req = HoneypotRequest(
            sessionId="test-history",
            message=Message(sender="scammer", text="New message"),
            conversationHistory=[
                ConversationMessage(sender="scammer", text="First"),
                ConversationMessage(sender="agent", text="Response"),
            ]
        )
        assert len(req.conversationHistory) == 2


class TestHoneypotResponse:
    """Tests for HoneypotResponse schema."""

    def test_valid_response(self):
        """Test creating a valid response."""
        resp = HoneypotResponse(
            status="success",
            reply="Tell me more about this lottery..."
        )
        assert resp.status == "success"
        assert resp.reply == "Tell me more about this lottery..."

    def test_default_status(self):
        """Test response with default status."""
        resp = HoneypotResponse(reply="Some reply")
        assert resp.status == "success"

    def test_response_requires_reply(self):
        """Test that reply is required."""
        with pytest.raises(ValidationError):
            HoneypotResponse(status="success")


class TestExtractedIntelligence:
    """Tests for ExtractedIntelligence schema."""

    def test_empty_intelligence(self):
        """Test creating empty intelligence."""
        intel = ExtractedIntelligence()
        assert intel.bankAccounts == []
        assert intel.upiIds == []
        assert intel.phishingLinks == []
        assert intel.phoneNumbers == []
        assert intel.suspiciousKeywords == []

    def test_populated_intelligence(self):
        """Test intelligence with data."""
        intel = ExtractedIntelligence(
            bankAccounts=["1234567890123"],
            upiIds=["scammer@ybl"],
            phishingLinks=["http://fake.com"],
            phoneNumbers=["9876543210"],
            suspiciousKeywords=["lottery", "otp"]
        )
        assert len(intel.bankAccounts) == 1
        assert len(intel.upiIds) == 1
        assert len(intel.suspiciousKeywords) == 2

    def test_intelligence_model_dump(self):
        """Test converting intelligence to dict."""
        intel = ExtractedIntelligence(
            upiIds=["test@ybl"],
            phoneNumbers=["9876543210"]
        )
        data = intel.model_dump()

        assert isinstance(data, dict)
        assert data["upiIds"] == ["test@ybl"]
        assert data["phoneNumbers"] == ["9876543210"]


class TestCallbackPayload:
    """Tests for CallbackPayload schema."""

    def test_valid_callback(self):
        """Test creating a valid callback payload."""
        callback = CallbackPayload(
            sessionId="test-callback",
            scamDetected=True,
            totalMessagesExchanged=10,
            extractedIntelligence={
                "upiIds": ["scammer@ybl"],
                "phoneNumbers": []
            },
            agentNotes="Lottery scam detected. Scammer requested OTP."
        )
        assert callback.sessionId == "test-callback"
        assert callback.scamDetected is True
        assert callback.totalMessagesExchanged == 10

    def test_callback_requires_all_fields(self):
        """Test that all fields are required."""
        with pytest.raises(ValidationError):
            CallbackPayload(
                sessionId="test",
                scamDetected=True
                # Missing other fields
            )


class TestSessionData:
    """Tests for SessionData schema."""

    def test_minimal_session(self):
        """Test creating a minimal session."""
        session = SessionData(session_id="test-session")

        assert session.session_id == "test-session"
        assert session.total_messages == 0
        assert session.scam_detected is False
        assert session.conversation_ended is False

    def test_session_defaults(self):
        """Test session default values."""
        session = SessionData(session_id="test")

        assert session.scam_confidence == 0.0
        assert session.scam_type is None
        assert session.callback_sent is False
        assert session.language == "English"
        assert len(session.conversation_history) == 0
        assert len(session.agent_notes) == 0

    def test_session_with_intelligence(self):
        """Test session with extracted intelligence."""
        intel = ExtractedIntelligence(upiIds=["test@ybl"])
        session = SessionData(
            session_id="intel-test",
            extracted_intelligence=intel
        )

        assert len(session.extracted_intelligence.upiIds) == 1

    def test_session_timestamps(self):
        """Test session timestamp fields."""
        session = SessionData(session_id="time-test")

        assert isinstance(session.created_at, datetime)
        assert isinstance(session.last_activity, datetime)

    def test_full_session(self):
        """Test fully populated session."""
        session = SessionData(
            session_id="full-test",
            created_at=datetime.utcnow(),
            last_activity=datetime.utcnow(),
            conversation_history=[
                {"role": "scammer", "content": "Hello"},
                {"role": "agent", "content": "Hi"}
            ],
            total_messages=2,
            scam_detected=True,
            scam_confidence=0.85,
            scam_type="lottery_scam",
            extracted_intelligence=ExtractedIntelligence(),
            agent_notes=["Scammer requested OTP"],
            conversation_ended=False,
            callback_sent=False,
            channel="SMS",
            language="Hindi"
        )

        assert session.total_messages == 2
        assert session.scam_type == "lottery_scam"
        assert session.language == "Hindi"
