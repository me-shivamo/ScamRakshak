"""
Tests for app/services/session_manager.py

Tests the session management functionality.
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock
from app.services.session_manager import SessionManager
from app.models.schemas import SessionData, ExtractedIntelligence


@pytest.fixture
def manager():
    """Create a fresh SessionManager instance."""
    return SessionManager()


class TestSessionCreation:
    """Tests for session creation."""

    @pytest.mark.asyncio
    async def test_create_new_session(self, manager):
        """Test creating a new session."""
        session = await manager.get_or_create("test-123")

        assert session is not None
        assert session.session_id == "test-123"
        assert session.total_messages == 0
        assert session.scam_detected is False

    @pytest.mark.asyncio
    async def test_create_with_metadata(self, manager):
        """Test creating session with channel and language."""
        session = await manager.get_or_create(
            "test-456",
            channel="WhatsApp",
            language="Hindi"
        )

        assert session.channel == "WhatsApp"
        assert session.language == "Hindi"

    @pytest.mark.asyncio
    async def test_get_existing_session(self, manager):
        """Test retrieving an existing session."""
        # Create session
        await manager.get_or_create("existing-123")

        # Get same session
        session = await manager.get_or_create("existing-123")

        assert session.session_id == "existing-123"

    @pytest.mark.asyncio
    async def test_session_has_default_intelligence(self, manager):
        """Test that new sessions have empty extracted intelligence."""
        session = await manager.get_or_create("test-intel")

        assert session.extracted_intelligence is not None
        assert isinstance(session.extracted_intelligence, ExtractedIntelligence)
        assert len(session.extracted_intelligence.upiIds) == 0


class TestSessionRetrieval:
    """Tests for session retrieval."""

    @pytest.mark.asyncio
    async def test_get_existing(self, manager):
        """Test getting an existing session."""
        await manager.get_or_create("get-test")
        session = await manager.get("get-test")

        assert session is not None
        assert session.session_id == "get-test"

    @pytest.mark.asyncio
    async def test_get_nonexistent(self, manager):
        """Test getting a non-existent session returns None."""
        session = await manager.get("does-not-exist")
        assert session is None


class TestSessionUpdate:
    """Tests for session updates."""

    @pytest.mark.asyncio
    async def test_update_session(self, manager):
        """Test updating session data."""
        session = await manager.get_or_create("update-test")
        session.scam_detected = True
        session.scam_confidence = 0.85
        session.total_messages = 5

        await manager.update("update-test", session)

        updated = await manager.get("update-test")
        assert updated.scam_detected is True
        assert updated.scam_confidence == 0.85
        assert updated.total_messages == 5

    @pytest.mark.asyncio
    async def test_update_updates_last_activity(self, manager):
        """Test that update refreshes last_activity time."""
        session = await manager.get_or_create("activity-test")
        original_time = session.last_activity

        # Small delay to ensure time difference
        import asyncio
        await asyncio.sleep(0.1)

        await manager.update("activity-test", session)

        updated = await manager.get("activity-test")
        assert updated.last_activity >= original_time


class TestSessionDeletion:
    """Tests for session deletion."""

    @pytest.mark.asyncio
    async def test_delete_session(self, manager):
        """Test deleting a session."""
        await manager.get_or_create("delete-test")
        result = await manager.delete("delete-test")

        assert result is True
        assert await manager.get("delete-test") is None

    @pytest.mark.asyncio
    async def test_delete_nonexistent(self, manager):
        """Test deleting non-existent session returns False."""
        result = await manager.delete("nonexistent")
        assert result is False


class TestInactiveSessions:
    """Tests for inactive session detection."""

    @pytest.mark.asyncio
    async def test_get_inactive_sessions(self, manager):
        """Test getting inactive sessions."""
        # Create a session with old last_activity
        session = await manager.get_or_create("inactive-test")
        session.last_activity = datetime.utcnow() - timedelta(seconds=600)
        # Directly set in the internal dict to avoid update() resetting last_activity
        manager._sessions["inactive-test"] = session

        # Get inactive sessions (threshold: 300 seconds)
        inactive = await manager.get_inactive_sessions(inactive_seconds=300)

        assert len(inactive) == 1
        assert inactive[0].session_id == "inactive-test"

    @pytest.mark.asyncio
    async def test_active_sessions_not_returned(self, manager):
        """Test that active sessions are not in inactive list."""
        # Create active session
        await manager.get_or_create("active-test")

        # Get inactive (should be empty)
        inactive = await manager.get_inactive_sessions(inactive_seconds=300)

        assert len(inactive) == 0

    @pytest.mark.asyncio
    async def test_callback_sent_excluded(self, manager):
        """Test that sessions with callback_sent=True are excluded."""
        session = await manager.get_or_create("callback-test")
        session.last_activity = datetime.utcnow() - timedelta(seconds=600)
        session.callback_sent = True
        await manager.update("callback-test", session)

        inactive = await manager.get_inactive_sessions(inactive_seconds=300)

        assert len([s for s in inactive if s.session_id == "callback-test"]) == 0


class TestExpiredSessions:
    """Tests for expired session detection and cleanup."""

    @pytest.mark.asyncio
    async def test_get_expired_sessions(self, manager):
        """Test getting expired sessions."""
        with patch("app.services.session_manager.settings") as mock_settings:
            mock_settings.SESSION_TTL_SECONDS = 3600

            # Create an expired session
            session = await manager.get_or_create("expired-test")
            session.created_at = datetime.utcnow() - timedelta(seconds=7200)
            manager._sessions["expired-test"] = session

            expired = await manager.get_expired_sessions()

            assert "expired-test" in expired

    @pytest.mark.asyncio
    async def test_cleanup_expired(self, manager):
        """Test cleanup of expired sessions."""
        with patch("app.services.session_manager.settings") as mock_settings:
            mock_settings.SESSION_TTL_SECONDS = 3600

            # Create expired sessions
            for i in range(3):
                session = await manager.get_or_create(f"expired-{i}")
                session.created_at = datetime.utcnow() - timedelta(seconds=7200)
                manager._sessions[f"expired-{i}"] = session

            # Create one active session
            await manager.get_or_create("active")

            count = await manager.cleanup_expired()

            assert count == 3
            assert await manager.get("active") is not None


class TestCallbackTracking:
    """Tests for callback tracking."""

    @pytest.mark.asyncio
    async def test_mark_callback_sent(self, manager):
        """Test marking callback as sent."""
        await manager.get_or_create("callback-mark-test")
        await manager.mark_callback_sent("callback-mark-test")

        session = await manager.get("callback-mark-test")
        assert session.callback_sent is True

    @pytest.mark.asyncio
    async def test_mark_callback_nonexistent(self, manager):
        """Test marking callback for non-existent session."""
        # Should not raise
        await manager.mark_callback_sent("nonexistent")

    @pytest.mark.asyncio
    async def test_mark_conversation_ended(self, manager):
        """Test marking conversation as ended."""
        await manager.get_or_create("end-test")
        await manager.mark_conversation_ended("end-test")

        session = await manager.get("end-test")
        assert session.conversation_ended is True


class TestStatistics:
    """Tests for session statistics."""

    @pytest.mark.asyncio
    async def test_get_stats_empty(self, manager):
        """Test stats with no sessions."""
        stats = manager.get_stats()

        assert stats["total_sessions"] == 0
        assert stats["active_sessions"] == 0
        assert stats["scams_detected"] == 0

    @pytest.mark.asyncio
    async def test_get_stats_with_sessions(self, manager):
        """Test stats with various sessions."""
        # Create sessions
        session1 = await manager.get_or_create("session-1")
        session2 = await manager.get_or_create("session-2")
        session3 = await manager.get_or_create("session-3")

        # Modify some
        session1.scam_detected = True
        session2.conversation_ended = True
        session3.scam_detected = True

        await manager.update("session-1", session1)
        await manager.update("session-2", session2)
        await manager.update("session-3", session3)

        stats = manager.get_stats()

        assert stats["total_sessions"] == 3
        assert stats["active_sessions"] == 2  # session-2 ended
        assert stats["scams_detected"] == 2


class TestConcurrency:
    """Tests for concurrent access safety."""

    @pytest.mark.asyncio
    async def test_concurrent_session_creation(self, manager):
        """Test that concurrent creates don't cause issues."""
        import asyncio

        async def create_session(session_id):
            return await manager.get_or_create(session_id)

        # Create multiple sessions concurrently
        tasks = [create_session(f"concurrent-{i}") for i in range(10)]
        sessions = await asyncio.gather(*tasks)

        assert len(sessions) == 10
        assert all(s is not None for s in sessions)

    @pytest.mark.asyncio
    async def test_concurrent_updates(self, manager):
        """Test that concurrent updates are safe."""
        import asyncio

        await manager.get_or_create("concurrent-update")

        async def update_session(value):
            session = await manager.get("concurrent-update")
            session.total_messages = value
            await manager.update("concurrent-update", session)

        tasks = [update_session(i) for i in range(10)]
        await asyncio.gather(*tasks)

        # Should complete without error
        session = await manager.get("concurrent-update")
        assert session is not None
