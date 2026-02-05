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
Hybrid extraction - Uses both regex patterns AND AI for comprehensive extraction:
- Regex catches standard formats reliably (UPI IDs, phone numbers, URLs)
- AI catches obfuscated data (numbers written as words) and context-dependent info
"""

import re
import logging
from typing import List, Set, Dict

from app.models.schemas import ExtractedIntelligence
from app.core.gemini_client import gemini_client
from app.utils.patterns import (
    UPI_PATTERN,
    PHONE_PATTERN,
    BANK_ACCOUNT_PATTERN,
    URL_PATTERN,
    EMAIL_PATTERN,
    SUSPICIOUS_KEYWORDS
)

logger = logging.getLogger(__name__)


class IntelligenceExtractor:
    """
    Extract actionable intelligence from scammer conversations.

    Uses hybrid extraction combining:
    - Regex patterns: Reliable extraction of standard formats (UPI IDs, phones, URLs)
    - AI extraction: Catches obfuscated data and context-dependent info

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
        Extract all intelligence from conversation using hybrid approach.

        Uses both regex patterns (for reliable standard format extraction)
        and AI (for obfuscated/context-dependent extraction).

        Args:
            conversation_history: List of messages with 'role' and 'content' keys
            existing: Previously extracted intelligence to merge with

        Returns:
            ExtractedIntelligence with all found data
        """
        logger.debug(f"Extracting intelligence from conversation with {len(conversation_history)} messages")

        # Combine all conversation text for regex extraction
        full_text = " ".join([
            msg.get("content", "") for msg in conversation_history
        ])

        # Step 1: Extract using regex patterns (reliable for standard formats)
        regex_intel = self._extract_with_regex(full_text)

        # Step 2: Use AI to extract intelligence (catches obfuscated data)
        ai_intel = await gemini_client.extract_intelligence_from_conversation(
            conversation_history
        )

        # Step 3: Merge regex results into ai_intel
        combined_intel = {
            "bankAccounts": list(set(ai_intel.get("bankAccounts", []) + regex_intel.get("bankAccounts", []))),
            "upiIds": list(set(ai_intel.get("upiIds", []) + regex_intel.get("upiIds", []))),
            "phoneNumbers": list(set(ai_intel.get("phoneNumbers", []) + regex_intel.get("phoneNumbers", []))),
            "phishingLinks": list(set(ai_intel.get("phishingLinks", []) + regex_intel.get("phishingLinks", []))),
            "suspiciousKeywords": list(set(ai_intel.get("suspiciousKeywords", []) + regex_intel.get("suspiciousKeywords", [])))
        }

        # Step 4: Merge with existing intelligence
        merged = self._merge_intelligence(combined_intel, existing)

        logger.info(
            f"Extracted: {len(merged.upiIds)} UPIs, "
            f"{len(merged.phoneNumbers)} phones, "
            f"{len(merged.bankAccounts)} bank accounts, "
            f"{len(merged.phishingLinks)} links, "
            f"{len(merged.suspiciousKeywords)} keywords"
        )

        return merged

    def _extract_with_regex(self, text: str) -> Dict:
        """
        Extract intelligence using regex patterns.

        This ensures standard format data is reliably captured
        even if AI misses it.

        Args:
            text: Full conversation text to analyze

        Returns:
            Dictionary with extracted data
        """
        # Extract UPI IDs - exclude email addresses
        upi_matches = re.findall(UPI_PATTERN, text, re.IGNORECASE)
        # Filter out email addresses (those with domain extensions like .com, .org)
        upi_ids = [
            upi for upi in upi_matches
            if not re.search(r'@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', upi)
        ]

        # Extract phone numbers and normalize to 10 digits
        phone_matches = re.findall(PHONE_PATTERN, text)
        phone_numbers = []
        for phone in phone_matches:
            # Remove +91, 91, spaces, dashes to get 10-digit number
            normalized = re.sub(r'[\+\-\s]', '', phone)
            if normalized.startswith('91') and len(normalized) > 10:
                normalized = normalized[2:]
            if len(normalized) == 10:
                phone_numbers.append(normalized)

        # Extract URLs
        urls = re.findall(URL_PATTERN, text)

        # Extract bank account numbers (be careful not to match phone numbers)
        bank_matches = re.findall(BANK_ACCOUNT_PATTERN, text)
        # Filter out phone numbers from bank account matches
        bank_accounts = [
            acc for acc in bank_matches
            if acc not in phone_numbers and len(acc) >= 9
        ]

        # Extract suspicious keywords
        text_lower = text.lower()
        keywords = [
            keyword for keyword in SUSPICIOUS_KEYWORDS
            if keyword.lower() in text_lower
        ]

        return {
            "bankAccounts": bank_accounts,
            "upiIds": upi_ids,
            "phoneNumbers": phone_numbers,
            "phishingLinks": urls,
            "suspiciousKeywords": keywords
        }

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
