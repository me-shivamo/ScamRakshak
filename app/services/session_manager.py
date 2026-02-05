"""
Session Manager - Stores Conversation State

When someone talks to our API, we need to remember:
- The conversation history
- Intelligence extracted
- Scam detection results
- Agent notes

This is called a "session" - all data for one conversation.

HOW IT WORKS:
- Sessions are stored in a Python dictionary (in RAM)
- Key = sessionId, Value = SessionData
- Each session has a timeout (TTL = Time To Live)
- Old sessions are automatically cleaned up

WHY IN-MEMORY?
- Fast: No database calls needed
- Simple: No setup required
- Good enough for hackathon

LIMITATION:
- Data is lost if server restarts
- For production, you'd use Redis or a database
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, Optional, List

from app.models.schemas import SessionData, ExtractedIntelligence
from app.config import settings

logger = logging.getLogger(__name__)


class SessionManager:
    """
    In-memory session storage with automatic cleanup.

    Usage:
        manager = SessionManager()

        # Get or create a session
        session = await manager.get_or_create("session_123")

        # Update session
        session.scam_detected = True
        await manager.update("session_123", session)

        # Get inactive sessions (for callback)
        inactive = await manager.get_inactive_sessions()
    """

    def __init__(self):
        """Initialize the session manager."""
        # Dictionary to store sessions: {session_id: SessionData}
        self._sessions: Dict[str, SessionData] = {}

        # Lock for thread-safe operations
        # (Multiple requests might access sessions at the same time)
        self._lock = asyncio.Lock()

        logger.info("Session manager initialized")

    async def get_or_create(
        self,
        session_id: str,
        channel: Optional[str] = None,
        language: Optional[str] = "English"
    ) -> SessionData:
        """
        Get existing session or create a new one.

        Args:
            session_id: Unique identifier for the session
            channel: Optional channel (SMS, WhatsApp, etc.)
            language: Language of conversation

        Returns:
            SessionData object

        Example:
            >>> session = await manager.get_or_create("abc123")
            >>> print(session.total_messages)
            0  # New session
        """
        async with self._lock:
            if session_id not in self._sessions:
                # Create new session
                self._sessions[session_id] = SessionData(
                    session_id=session_id,
                    channel=channel,
                    language=language,
                    created_at=datetime.utcnow(),
                    last_activity=datetime.utcnow(),
                    extracted_intelligence=ExtractedIntelligence()
                )
                logger.info(f"Created new session: {session_id}")
            else:
                # Update last activity time
                self._sessions[session_id].last_activity = datetime.utcnow()

            return self._sessions[session_id]

    async def get(self, session_id: str) -> Optional[SessionData]:
        """
        Get a session by ID.

        Returns None if session doesn't exist.
        """
        return self._sessions.get(session_id)

    async def update(self, session_id: str, session: SessionData) -> None:
        """
        Update a session's data.

        Args:
            session_id: Session to update
            session: New session data
        """
        async with self._lock:
            session.last_activity = datetime.utcnow()
            self._sessions[session_id] = session
            logger.debug(f"Updated session: {session_id}")

    async def delete(self, session_id: str) -> bool:
        """
        Delete a session.

        Returns True if session was deleted, False if not found.
        """
        async with self._lock:
            if session_id in self._sessions:
                del self._sessions[session_id]
                logger.info(f"Deleted session: {session_id}")
                return True
            return False

    async def get_inactive_sessions(
        self,
        inactive_seconds: Optional[int] = None
    ) -> List[SessionData]:
        """
        Get sessions that have been inactive for too long.

        These sessions are candidates for:
        - Sending the final callback to GUVI
        - Cleanup

        Args:
            inactive_seconds: Override the default inactivity threshold

        Returns:
            List of inactive sessions
        """
        if inactive_seconds is None:
            inactive_seconds = settings.MAX_INACTIVE_SECONDS

        cutoff_time = datetime.utcnow() - timedelta(seconds=inactive_seconds)
        inactive = []

        for session in self._sessions.values():
            # Check if session is inactive and callback hasn't been sent
            if session.last_activity < cutoff_time and not session.callback_sent:
                inactive.append(session)

        return inactive

    async def get_expired_sessions(self) -> List[str]:
        """
        Get session IDs that have exceeded their TTL.

        These sessions should be deleted.
        """
        cutoff_time = datetime.utcnow() - timedelta(seconds=settings.SESSION_TTL_SECONDS)
        expired = []

        for session_id, session in self._sessions.items():
            if session.created_at < cutoff_time:
                expired.append(session_id)

        return expired

    async def cleanup_expired(self) -> int:
        """
        Remove expired sessions.

        Returns the number of sessions deleted.
        """
        expired_ids = await self.get_expired_sessions()

        for session_id in expired_ids:
            await self.delete(session_id)

        if expired_ids:
            logger.info(f"Cleaned up {len(expired_ids)} expired sessions")

        return len(expired_ids)

    async def mark_callback_sent(self, session_id: str) -> None:
        """
        Mark that the callback has been sent for a session.

        This prevents duplicate callbacks.
        """
        async with self._lock:
            if session_id in self._sessions:
                self._sessions[session_id].callback_sent = True
                logger.info(f"Marked callback sent for session: {session_id}")

    async def mark_conversation_ended(self, session_id: str) -> None:
        """
        Mark that the conversation has ended.
        """
        async with self._lock:
            if session_id in self._sessions:
                self._sessions[session_id].conversation_ended = True
                logger.info(f"Marked conversation ended for session: {session_id}")

    def get_stats(self) -> dict:
        """
        Get statistics about sessions.

        Useful for monitoring/debugging.
        """
        total = len(self._sessions)
        active = sum(1 for s in self._sessions.values() if not s.conversation_ended)
        scams = sum(1 for s in self._sessions.values() if s.scam_detected)

        return {
            "total_sessions": total,
            "active_sessions": active,
            "scams_detected": scams
        }


# Create singleton instance
session_manager = SessionManager()
