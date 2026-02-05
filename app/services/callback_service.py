"""
GUVI Callback Service - Send Final Results

This service sends the final intelligence report to GUVI when
a scam conversation ends. This is MANDATORY for scoring!

WHEN TO SEND:
- When conversation has been inactive for 5 minutes
- When scammer stops responding
- When conversation explicitly ends

WHAT WE SEND:
{
    "sessionId": "abc123",
    "scamDetected": true,
    "totalMessagesExchanged": 18,
    "extractedIntelligence": {
        "bankAccounts": [...],
        "upiIds": [...],
        "phishingLinks": [...],
        "phoneNumbers": [...],
        "suspiciousKeywords": [...]
    },
    "agentNotes": "Summary of the scam..."
}

IMPORTANT:
If this callback is not sent, GUVI cannot evaluate the solution!
"""

import logging
import httpx
from typing import Optional

from app.config import settings
from app.models.schemas import SessionData, CallbackPayload

logger = logging.getLogger(__name__)


class CallbackService:
    """
    Service to send final results to GUVI evaluation endpoint.

    Usage:
        service = CallbackService()
        success = await service.send_callback(session)
    """

    def __init__(self):
        """Initialize the callback service."""
        self.callback_url = settings.GUVI_CALLBACK_URL
        self.timeout = 30.0  # 30 seconds timeout

        logger.info(f"Callback service initialized. URL: {self.callback_url}")

    async def send_callback(self, session: SessionData) -> bool:
        """
        Send final results to GUVI callback endpoint.

        Args:
            session: The session data to report

        Returns:
            True if callback was sent successfully, False otherwise

        Example:
            >>> success = await service.send_callback(session)
            >>> if success:
            ...     print("Callback sent!")
        """
        # Build the payload
        payload = self._build_payload(session)

        logger.info(
            f"Sending callback for session {session.session_id}. "
            f"Scam: {session.scam_detected}, Messages: {session.total_messages}"
        )

        try:
            # Send HTTP POST request to GUVI
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.callback_url,
                    json=payload.model_dump(),
                    timeout=self.timeout,
                    headers={"Content-Type": "application/json"}
                )

                # Check if successful
                if response.status_code == 200:
                    logger.info(f"Callback sent successfully for session {session.session_id}")
                    return True
                else:
                    logger.error(
                        f"Callback failed for session {session.session_id}. "
                        f"Status: {response.status_code}, Response: {response.text}"
                    )
                    return False

        except httpx.TimeoutException:
            logger.error(f"Callback timeout for session {session.session_id}")
            return False

        except httpx.ConnectError:
            logger.error(f"Callback connection error for session {session.session_id}")
            return False

        except Exception as e:
            logger.error(f"Callback error for session {session.session_id}: {e}")
            return False

    def _build_payload(self, session: SessionData) -> CallbackPayload:
        """
        Build the callback payload from session data.

        Converts our internal SessionData format to the
        format GUVI expects.
        """
        # Build agent notes summary
        agent_notes = self._build_agent_notes(session)

        # Build extracted intelligence dict
        intel_dict = {
            "bankAccounts": session.extracted_intelligence.bankAccounts,
            "upiIds": session.extracted_intelligence.upiIds,
            "phishingLinks": session.extracted_intelligence.phishingLinks,
            "phoneNumbers": session.extracted_intelligence.phoneNumbers,
            "suspiciousKeywords": session.extracted_intelligence.suspiciousKeywords
        }

        return CallbackPayload(
            sessionId=session.session_id,
            scamDetected=session.scam_detected,
            totalMessagesExchanged=session.total_messages,
            extractedIntelligence=intel_dict,
            agentNotes=agent_notes
        )

    def _build_agent_notes(self, session: SessionData) -> str:
        """
        Build a summary of agent notes for the callback.
        """
        parts = []

        # Add scam type and confidence
        if session.scam_type:
            parts.append(f"Scam Type: {session.scam_type}")
            parts.append(f"Confidence: {session.scam_confidence:.0%}")

        # Add conversation summary
        parts.append(f"Total messages: {session.total_messages}")

        # Add channel info
        if session.channel:
            parts.append(f"Channel: {session.channel}")

        # Add intelligence summary
        intel = session.extracted_intelligence
        intel_parts = []
        if intel.upiIds:
            intel_parts.append(f"{len(intel.upiIds)} UPI IDs")
        if intel.phoneNumbers:
            intel_parts.append(f"{len(intel.phoneNumbers)} phone numbers")
        if intel.phishingLinks:
            intel_parts.append(f"{len(intel.phishingLinks)} links")
        if intel.bankAccounts:
            intel_parts.append(f"{len(intel.bankAccounts)} bank accounts")

        if intel_parts:
            parts.append(f"Intelligence gathered: {', '.join(intel_parts)}")

        # Add agent notes from conversation
        if session.agent_notes:
            parts.append("\nAgent observations:")
            # Add last 5 notes
            for note in session.agent_notes[-5:]:
                parts.append(f"- {note}")

        return "\n".join(parts)

    async def send_callback_with_retry(
        self,
        session: SessionData,
        max_retries: int = 3
    ) -> bool:
        """
        Send callback with automatic retry on failure.

        Args:
            session: Session to report
            max_retries: Maximum number of retry attempts

        Returns:
            True if eventually successful
        """
        for attempt in range(max_retries):
            success = await self.send_callback(session)
            if success:
                return True

            logger.warning(
                f"Callback attempt {attempt + 1}/{max_retries} failed "
                f"for session {session.session_id}"
            )

        logger.error(
            f"All callback attempts failed for session {session.session_id}"
        )
        return False


# Create singleton instance
callback_service = CallbackService()
