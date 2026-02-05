"""
Pydantic Schemas for ScamRakshak API

This file defines the "shape" of data flowing through our API.
Think of these as CONTRACTS that specify:
- What data we EXPECT to receive
- What data we PROMISE to send back

ANALOGY: Like a form template
- Request schemas = "Please fill this form"
- Response schemas = "You'll get this receipt"
"""

from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


# ============================================================
# REQUEST SCHEMAS - What we receive from GUVI/scammers
# ============================================================

class Message(BaseModel):
    """
    A single message in the conversation.

    Example:
    {
        "sender": "scammer",
        "text": "You won a lottery!",
        "timestamp": 1770005528731
    }
    """
    sender: str = Field(
        ...,  # ... means REQUIRED
        description="Who sent the message: 'scammer' or 'user'"
    )
    text: str = Field(
        ...,
        description="The actual message content"
    )
    timestamp: Optional[int] = Field(
        default=None,
        description="Unix timestamp in milliseconds (optional)"
    )


class ConversationMessage(BaseModel):
    """
    A message in the conversation history.
    Simpler than Message - just role and content.
    """
    sender: str
    text: str
    timestamp: Optional[int] = None


class Metadata(BaseModel):
    """
    Optional metadata about the conversation.

    Example:
    {
        "channel": "SMS",
        "language": "English",
        "locale": "IN"
    }
    """
    channel: Optional[str] = Field(
        default=None,
        description="Communication channel: SMS, WhatsApp, Email, Chat"
    )
    language: Optional[str] = Field(
        default="English",
        description="Language of the conversation"
    )
    locale: Optional[str] = Field(
        default="IN",
        description="Country/region code"
    )


class HoneypotRequest(BaseModel):
    """
    The main request we receive from GUVI platform.

    This is what the API endpoint expects to receive.

    Example:
    {
        "sessionId": "abc123",
        "message": {"sender": "scammer", "text": "You won lottery!"},
        "conversationHistory": [],
        "metadata": {"channel": "SMS"}
    }
    """
    sessionId: str = Field(
        ...,
        description="Unique identifier for this conversation session"
    )
    message: Message = Field(
        ...,
        description="The current message from the scammer"
    )
    conversationHistory: Optional[List[ConversationMessage]] = Field(
        default=[],
        description="Previous messages in this conversation (empty for first message)"
    )
    metadata: Optional[Metadata] = Field(
        default=None,
        description="Optional metadata about the channel, language, etc."
    )


# ============================================================
# RESPONSE SCHEMAS - What we send back
# ============================================================

class HoneypotResponse(BaseModel):
    """
    Our response to each message.

    Simple format required by GUVI:
    {
        "status": "success",
        "reply": "Oh really? Tell me more beta..."
    }
    """
    status: str = Field(
        default="success",
        description="Status of the response: 'success' or 'error'"
    )
    reply: str = Field(
        ...,
        description="The honeypot's reply to the scammer"
    )


# ============================================================
# INTELLIGENCE SCHEMAS - Data we extract from scammers
# ============================================================

class ExtractedIntelligence(BaseModel):
    """
    Information extracted from the scammer's messages.

    We look for:
    - Bank account numbers
    - UPI IDs (like name@ybl, phone@paytm)
    - Phone numbers
    - Phishing links/URLs
    - Suspicious keywords

    Example:
    {
        "bankAccounts": ["1234567890123"],
        "upiIds": ["scammer@ybl"],
        "phoneNumbers": ["+919876543210"],
        "phishingLinks": ["http://fake-bank.com"],
        "suspiciousKeywords": ["urgent", "lottery", "blocked"]
    }
    """
    bankAccounts: List[str] = Field(
        default=[],
        description="Bank account numbers found in messages"
    )
    upiIds: List[str] = Field(
        default=[],
        description="UPI IDs found (e.g., name@ybl, phone@paytm)"
    )
    phishingLinks: List[str] = Field(
        default=[],
        description="Suspicious URLs/links found"
    )
    phoneNumbers: List[str] = Field(
        default=[],
        description="Phone numbers found"
    )
    suspiciousKeywords: List[str] = Field(
        default=[],
        description="Scam-related keywords detected"
    )


# ============================================================
# CALLBACK SCHEMA - What we send to GUVI at the end
# ============================================================

class CallbackPayload(BaseModel):
    """
    Final results sent to GUVI callback endpoint.

    This is MANDATORY - GUVI uses this to score our solution.

    Sent to: POST https://hackathon.guvi.in/api/updateHoneyPotFinalResult
    """
    sessionId: str = Field(
        ...,
        description="The session ID from the original request"
    )
    scamDetected: bool = Field(
        ...,
        description="Whether we detected this as a scam"
    )
    totalMessagesExchanged: int = Field(
        ...,
        description="Total number of messages in the conversation"
    )
    extractedIntelligence: Dict[str, Any] = Field(
        ...,
        description="All intelligence extracted (UPI, phones, links, etc.)"
    )
    agentNotes: str = Field(
        ...,
        description="Summary of the scam and agent's observations"
    )


# ============================================================
# SESSION SCHEMA - Internal state tracking
# ============================================================

class SessionData(BaseModel):
    """
    Internal data structure to track a conversation session.

    NOT sent to/from API - used internally to remember:
    - Conversation history
    - Scam detection results
    - Extracted intelligence
    - Agent notes
    """
    session_id: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    last_activity: datetime = Field(default_factory=datetime.utcnow)

    # Conversation tracking
    conversation_history: List[Dict[str, str]] = Field(default=[])
    total_messages: int = Field(default=0)

    # Scam detection state
    scam_detected: bool = Field(default=False)
    scam_confidence: float = Field(default=0.0)
    scam_type: Optional[str] = Field(default=None)

    # Intelligence collected
    extracted_intelligence: ExtractedIntelligence = Field(
        default_factory=ExtractedIntelligence
    )

    # Agent tracking
    agent_notes: List[str] = Field(default=[])

    # Status flags
    conversation_ended: bool = Field(default=False)
    callback_sent: bool = Field(default=False)

    # Metadata
    channel: Optional[str] = Field(default=None)
    language: Optional[str] = Field(default="English")
