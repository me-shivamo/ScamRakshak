"""
Intelligence Extraction Module

This module extracts valuable information from scammer messages:
- Phone numbers
- UPI IDs
- Bank account numbers
- Phishing links/URLs
- Suspicious keywords

WHY IS THIS IMPORTANT?
The information we extract helps catch scammers!
GUVI evaluates us on the quality of intelligence we gather.

EXTRACTION METHOD:
AI-only extraction - Uses LLM to comprehensively extract all intelligence
from the entire conversation history. This catches:
- Standard formats (phone numbers, UPI IDs, etc.)
- Obfuscated data (numbers written as words)
- Context-dependent information
"""

import logging
from typing import List, Set, Dict

from app.models.schemas import ExtractedIntelligence
from app.core.gemini_client import gemini_client

logger = logging.getLogger(__name__)


class IntelligenceExtractor:
    """
    Extract actionable intelligence from scammer conversations.

    Uses AI-only extraction to comprehensively analyze the entire
    conversation history and extract all intelligence.

    Usage:
        extractor = IntelligenceExtractor()
        intel = await extractor.extract_from_conversation(
            conversation_history=[
                {"role": "scammer", "content": "Send to my UPI scammer@ybl"},
                {"role": "agent", "content": "What is your phone number?"},
                {"role": "scammer", "content": "Call me at 9876543210"}
            ],
            existing=previous_intel
        )
    """

    async def extract_from_conversation(
        self,
        conversation_history: List[Dict[str, str]],
        existing: ExtractedIntelligence = None
    ) -> ExtractedIntelligence:
        """
        Extract all intelligence from conversation using AI.

        Args:
            conversation_history: List of messages with 'role' and 'content' keys
            existing: Previously extracted intelligence to merge with

        Returns:
            ExtractedIntelligence with all found data
        """
        logger.debug(f"Extracting intelligence from conversation with {len(conversation_history)} messages")

        # Use AI to extract intelligence from entire conversation
        ai_intel = await gemini_client.extract_intelligence_from_conversation(
            conversation_history
        )

        # Merge with existing intelligence
        merged = self._merge_intelligence(ai_intel, existing)

        logger.info(
            f"Extracted: {len(merged.upiIds)} UPIs, "
            f"{len(merged.phoneNumbers)} phones, "
            f"{len(merged.bankAccounts)} bank accounts, "
            f"{len(merged.phishingLinks)} links, "
            f"{len(merged.suspiciousKeywords)} keywords"
        )

        return merged

    async def extract(
        self,
        text: str,
        existing: ExtractedIntelligence = None
    ) -> ExtractedIntelligence:
        """
        Extract intelligence from a single text message.

        This wraps the text in a conversation format and calls
        the conversation-based extraction.

        Args:
            text: Message text to analyze
            existing: Previously extracted intelligence to merge with

        Returns:
            ExtractedIntelligence with all found data
        """
        # Wrap single text in conversation format
        conversation = [{"role": "scammer", "content": text}]
        return await self.extract_from_conversation(conversation, existing)

    def _merge_intelligence(
        self,
        ai_intel: Dict,
        existing: ExtractedIntelligence = None
    ) -> ExtractedIntelligence:
        """
        Merge AI extraction results with existing intelligence.

        Args:
            ai_intel: Dictionary from AI extraction
            existing: Previously extracted intelligence

        Returns:
            Merged ExtractedIntelligence object
        """
        existing = existing or ExtractedIntelligence()

        def merge_lists(new_items: List, existing_items: List) -> List[str]:
            """Merge two lists, removing duplicates."""
            merged: Set[str] = set()
            for item in existing_items or []:
                merged.add(str(item).lower())
            for item in new_items or []:
                merged.add(str(item).lower())
            return list(merged)

        return ExtractedIntelligence(
            bankAccounts=merge_lists(
                ai_intel.get("bankAccounts", []),
                existing.bankAccounts
            ),
            upiIds=merge_lists(
                ai_intel.get("upiIds", []),
                existing.upiIds
            ),
            phoneNumbers=merge_lists(
                ai_intel.get("phoneNumbers", []),
                existing.phoneNumbers
            ),
            phishingLinks=merge_lists(
                ai_intel.get("phishingLinks", []),
                existing.phishingLinks
            ),
            suspiciousKeywords=merge_lists(
                ai_intel.get("suspiciousKeywords", []),
                existing.suspiciousKeywords
            )
        )


# Create singleton instance
intelligence_extractor = IntelligenceExtractor()
