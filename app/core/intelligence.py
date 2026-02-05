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

TWO EXTRACTION METHODS:
1. Regex (fast) - Pattern matching for standard formats
2. AI (smart) - Catches tricks like "nine eight seven six..."
"""

import re
import logging
from typing import List, Set

from app.models.schemas import ExtractedIntelligence
from app.utils.patterns import (
    UPI_PATTERN,
    BANK_ACCOUNT_PATTERN,
    PHONE_PATTERN,
    URL_PATTERN,
    EMAIL_PATTERN,
    SUSPICIOUS_KEYWORDS
)
from app.core.gemini_client import gemini_client

logger = logging.getLogger(__name__)


class IntelligenceExtractor:
    """
    Extract actionable intelligence from scammer messages.

    Combines regex pattern matching (fast) with AI extraction (smart)
    to capture as much information as possible.

    Usage:
        extractor = IntelligenceExtractor()
        intel = await extractor.extract(
            text="Send to my UPI scammer@ybl or call 9876543210",
            existing=previous_intel
        )
    """

    async def extract(
        self,
        text: str,
        existing: ExtractedIntelligence = None
    ) -> ExtractedIntelligence:
        """
        Extract all intelligence from text.

        Args:
            text: Message text to analyze
            existing: Previously extracted intelligence to merge with

        Returns:
            ExtractedIntelligence with all found data

        Example:
            >>> intel = await extractor.extract(
            ...     "Send money to my UPI scammer@ybl, call 9876543210"
            ... )
            >>> print(intel.upiIds)
            ['scammer@ybl']
            >>> print(intel.phoneNumbers)
            ['9876543210']
        """
        logger.debug(f"Extracting intelligence from: {text[:100]}...")

        # Step 1: Regex-based extraction (fast)
        regex_intel = self._extract_with_regex(text)

        # Step 2: AI-based extraction (catches edge cases)
        ai_intel = await self._extract_with_ai(text)

        # Step 3: Merge all results
        merged = self._merge_intelligence(regex_intel, ai_intel, existing)

        logger.info(
            f"Extracted: {len(merged.upiIds)} UPIs, "
            f"{len(merged.phoneNumbers)} phones, "
            f"{len(merged.phishingLinks)} links, "
            f"{len(merged.suspiciousKeywords)} keywords"
        )

        return merged

    def _extract_with_regex(self, text: str) -> ExtractedIntelligence:
        """
        Fast regex-based extraction.

        Uses pre-defined patterns to find:
        - UPI IDs (name@bank format)
        - Phone numbers (Indian format)
        - Bank account numbers (9-18 digits)
        - URLs
        - Suspicious keywords
        """
        return ExtractedIntelligence(
            upiIds=self._find_upi_ids(text),
            phoneNumbers=self._find_phone_numbers(text),
            bankAccounts=self._find_bank_accounts(text),
            phishingLinks=self._find_urls(text),
            suspiciousKeywords=self._find_suspicious_keywords(text)
        )

    def _find_upi_ids(self, text: str) -> List[str]:
        """
        Find UPI IDs in text.

        UPI format: username@bankhandle
        Examples: ramesh@ybl, 9876543210@paytm, user.name@okaxis
        """
        found = re.findall(UPI_PATTERN, text, re.IGNORECASE)

        # Filter out email addresses (they match UPI pattern too)
        # UPI handles are short, emails have longer domains
        valid_upi_handles = [
            'ybl', 'paytm', 'okaxis', 'oksbi', 'okicici', 'okhdfcbank',
            'apl', 'yapl', 'upi', 'ibl', 'axl', 'sbi', 'icici',
            'hdfcbank', 'axisbank', 'kotak', 'barodampay', 'aubank',
            'jupiteraxis', 'fbl', 'waicici', 'wahdfcbank', 'wasbi'
        ]

        upi_ids = []
        for match in found:
            handle = match.split('@')[1].lower()
            # Check if it's a known UPI handle or short enough to be UPI
            if handle in valid_upi_handles or len(handle) <= 10:
                upi_ids.append(match.lower())

        return list(set(upi_ids))  # Remove duplicates

    def _find_phone_numbers(self, text: str) -> List[str]:
        """
        Find Indian phone numbers.

        Formats matched:
        - 9876543210
        - +91 9876543210
        - +91-9876543210
        - 91 98765 43210
        """
        raw_numbers = re.findall(PHONE_PATTERN, text)
        normalized = set()

        for num in raw_numbers:
            # Remove all non-digits
            clean = re.sub(r'[^\d]', '', num)

            # If starts with 91 and has 12 digits, remove 91
            if clean.startswith('91') and len(clean) == 12:
                clean = clean[2:]

            # Valid Indian mobile numbers are 10 digits starting with 6-9
            if len(clean) == 10 and clean[0] in '6789':
                normalized.add(clean)

        return list(normalized)

    def _find_bank_accounts(self, text: str) -> List[str]:
        """
        Find potential bank account numbers.

        Indian bank accounts: 9-18 digits
        We look for numbers that could be account numbers.
        """
        # Find all 9-18 digit numbers
        potential = re.findall(BANK_ACCOUNT_PATTERN, text)

        # Filter out phone numbers and timestamps
        accounts = []
        for num in potential:
            # Skip if it looks like a phone number (10 digits starting with 6-9)
            if len(num) == 10 and num[0] in '6789':
                continue
            # Skip if it looks like a timestamp (13 digits)
            if len(num) == 13:
                continue
            accounts.append(num)

        return list(set(accounts))

    def _find_urls(self, text: str) -> List[str]:
        """
        Find URLs/links in text.

        These are often phishing links.
        """
        urls = re.findall(URL_PATTERN, text)
        return list(set(urls))

    def _find_suspicious_keywords(self, text: str) -> List[str]:
        """
        Find scam-related keywords in text.
        """
        text_lower = text.lower()
        found = []

        for keyword in SUSPICIOUS_KEYWORDS:
            if keyword in text_lower:
                found.append(keyword)

        return found

    async def _extract_with_ai(self, text: str) -> dict:
        """
        Use AI to extract information regex might miss.

        AI can catch:
        - Numbers written as words ("nine eight seven...")
        - Obfuscated text ("l0ttery" instead of "lottery")
        - Context-dependent extraction
        """
        try:
            return await gemini_client.extract_intelligence(text)
        except Exception as e:
            logger.warning(f"AI extraction failed: {e}")
            return {}

    def _merge_intelligence(
        self,
        regex: ExtractedIntelligence,
        ai: dict,
        existing: ExtractedIntelligence = None
    ) -> ExtractedIntelligence:
        """
        Merge intelligence from all sources.

        Combines:
        - Regex extraction results
        - AI extraction results
        - Previously extracted data (existing)

        Removes duplicates automatically.
        """
        existing = existing or ExtractedIntelligence()

        def merge_lists(*lists) -> List[str]:
            """Merge multiple lists, removing duplicates."""
            merged: Set[str] = set()
            for lst in lists:
                if lst:
                    # Convert to lowercase for consistent deduplication
                    merged.update(str(item).lower() for item in lst)
            return list(merged)

        return ExtractedIntelligence(
            bankAccounts=merge_lists(
                regex.bankAccounts,
                ai.get("bank_accounts", []),
                existing.bankAccounts
            ),
            upiIds=merge_lists(
                regex.upiIds,
                ai.get("upi_ids", []),
                existing.upiIds
            ),
            phoneNumbers=merge_lists(
                regex.phoneNumbers,
                ai.get("phone_numbers", []),
                existing.phoneNumbers
            ),
            phishingLinks=merge_lists(
                regex.phishingLinks,
                ai.get("urls", []),
                existing.phishingLinks
            ),
            suspiciousKeywords=merge_lists(
                regex.suspiciousKeywords,
                existing.suspiciousKeywords
            )
        )


# Create singleton instance
intelligence_extractor = IntelligenceExtractor()
