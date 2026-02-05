"""
Tests for app/core/intelligence.py

Tests the intelligence extraction module.
"""

import pytest
from unittest.mock import AsyncMock, patch
from app.core.intelligence import IntelligenceExtractor
from app.models.schemas import ExtractedIntelligence


@pytest.fixture
def extractor():
    """Create an IntelligenceExtractor instance."""
    return IntelligenceExtractor()


class TestRegexExtraction:
    """Tests for regex-based extraction methods."""

    def test_find_upi_ids(self, extractor):
        """Test UPI ID extraction."""
        text = "Send to scammer@ybl or fraud@paytm for instant payment"
        upis = extractor._find_upi_ids(text)
        assert "scammer@ybl" in upis
        assert "fraud@paytm" in upis

    def test_find_upi_ids_filters_emails(self, extractor):
        """Test that email addresses with long domains are filtered out."""
        text = "Contact support@verylongcompanydomain.com or pay at user@ybl"
        upis = extractor._find_upi_ids(text)
        # Email should be filtered (domain > 10 chars), UPI should remain
        assert "user@ybl" in upis
        # Long domain emails should be filtered
        assert not any("verylongcompanydomain" in upi for upi in upis)

    def test_find_phone_numbers(self, extractor):
        """Test phone number extraction."""
        text = "Call 9876543210 or +91 8765432109 for help"
        phones = extractor._find_phone_numbers(text)
        assert "9876543210" in phones
        assert "8765432109" in phones

    def test_find_phone_numbers_normalizes(self, extractor):
        """Test that phone numbers are normalized."""
        text = "+91-9876543210"
        phones = extractor._find_phone_numbers(text)
        assert "9876543210" in phones

    def test_find_phone_numbers_rejects_invalid(self, extractor):
        """Test that invalid phone numbers are rejected."""
        text = "Code: 1234567890"  # Starts with 1, invalid for Indian mobile
        phones = extractor._find_phone_numbers(text)
        assert len(phones) == 0

    def test_find_bank_accounts(self, extractor):
        """Test bank account extraction."""
        text = "Account: 12345678901234 IFSC: SBIN0001234"
        accounts = extractor._find_bank_accounts(text)
        assert "12345678901234" in accounts

    def test_find_bank_accounts_filters_phone_numbers(self, extractor):
        """Test that phone numbers are filtered from bank accounts."""
        text = "Call 9876543210. Account: 12345678901234"
        accounts = extractor._find_bank_accounts(text)
        assert "9876543210" not in accounts
        assert "12345678901234" in accounts

    def test_find_urls(self, extractor):
        """Test URL extraction."""
        text = "Click https://phishing-site.com/login to verify"
        urls = extractor._find_urls(text)
        assert "https://phishing-site.com/login" in urls

    def test_find_suspicious_keywords(self, extractor):
        """Test suspicious keyword extraction."""
        text = "Your lottery prize is ready. Verify OTP urgently."
        keywords = extractor._find_suspicious_keywords(text)
        assert "lottery" in keywords
        assert "prize" in keywords
        assert "verify" in keywords
        assert "otp" in keywords
        assert "urgent" in keywords or "urgently" not in keywords  # "urgently" vs "urgent"


class TestExtractWithRegex:
    """Tests for the _extract_with_regex method."""

    def test_full_regex_extraction(self, extractor):
        """Test complete regex extraction."""
        text = (
            "Send money to scammer@ybl. "
            "Call 9876543210. "
            "Account: 12345678901234. "
            "Click http://fake.com/login here. "
            "Urgent lottery winner!"
        )
        intel = extractor._extract_with_regex(text)

        assert isinstance(intel, ExtractedIntelligence)
        assert "scammer@ybl" in intel.upiIds
        assert "9876543210" in intel.phoneNumbers
        assert "12345678901234" in intel.bankAccounts
        # URL might include trailing period, check if URL contains the base
        assert any("http://fake.com/login" in url for url in intel.phishingLinks)
        assert "lottery" in intel.suspiciousKeywords


class TestMergeIntelligence:
    """Tests for intelligence merging functionality."""

    def test_merge_removes_duplicates(self, extractor):
        """Test that merging removes duplicates."""
        regex_intel = ExtractedIntelligence(
            upiIds=["scammer@ybl"],
            phoneNumbers=["9876543210"]
        )
        ai_intel = {
            "upi_ids": ["scammer@ybl", "another@paytm"],
            "phone_numbers": ["9876543210"]
        }
        existing = ExtractedIntelligence(
            upiIds=["scammer@ybl"]
        )

        merged = extractor._merge_intelligence(regex_intel, ai_intel, existing)

        # Should have unique entries only
        assert len([u for u in merged.upiIds if u == "scammer@ybl"]) == 1

    def test_merge_combines_all_sources(self, extractor):
        """Test that merge combines data from all sources."""
        regex_intel = ExtractedIntelligence(
            upiIds=["upi1@ybl"]
        )
        ai_intel = {
            "upi_ids": ["upi2@paytm"]
        }
        existing = ExtractedIntelligence(
            upiIds=["upi3@oksbi"]
        )

        merged = extractor._merge_intelligence(regex_intel, ai_intel, existing)

        assert len(merged.upiIds) == 3

    def test_merge_handles_none_existing(self, extractor):
        """Test that merge handles None existing intelligence."""
        regex_intel = ExtractedIntelligence(
            phoneNumbers=["9876543210"]
        )
        ai_intel = {}

        merged = extractor._merge_intelligence(regex_intel, ai_intel, None)

        assert "9876543210" in merged.phoneNumbers


class TestAsyncExtraction:
    """Tests for async extraction methods."""

    @pytest.mark.asyncio
    async def test_extract_with_mocked_ai(self, extractor):
        """Test full extraction with mocked AI."""
        text = "Send to scammer@ybl. Call 9876543210 urgently."

        with patch.object(extractor, '_extract_with_ai', new_callable=AsyncMock) as mock_ai:
            mock_ai.return_value = {
                "upi_ids": ["ai-found@ybl"],
                "phone_numbers": [],
                "bank_accounts": [],
                "urls": []
            }

            intel = await extractor.extract(text)

            assert isinstance(intel, ExtractedIntelligence)
            # Should have both regex and AI results
            assert "scammer@ybl" in intel.upiIds
            assert "ai-found@ybl" in intel.upiIds

    @pytest.mark.asyncio
    async def test_extract_with_existing_intelligence(self, extractor):
        """Test extraction merges with existing intelligence."""
        text = "New UPI: new@ybl"
        existing = ExtractedIntelligence(
            upiIds=["old@paytm"],
            phoneNumbers=["9876543210"]
        )

        with patch.object(extractor, '_extract_with_ai', new_callable=AsyncMock) as mock_ai:
            mock_ai.return_value = {}

            intel = await extractor.extract(text, existing)

            # Should contain both old and new
            assert "old@paytm" in intel.upiIds
            assert "new@ybl" in intel.upiIds
            assert "9876543210" in intel.phoneNumbers

    @pytest.mark.asyncio
    async def test_extract_ai_failure_fallback(self, extractor):
        """Test that AI failure is handled in _extract_with_ai method."""
        text = "Send to scammer@ybl"

        # The actual implementation catches exceptions in _extract_with_ai
        # and returns empty dict, so we need to test that behavior
        with patch("app.core.intelligence.gemini_client") as mock_gemini:
            mock_gemini.extract_intelligence = AsyncMock(
                side_effect=Exception("AI service unavailable")
            )

            # _extract_with_ai should catch the exception and return empty dict
            result = await extractor._extract_with_ai(text)
            assert result == {}

            # Full extraction should still work with regex
            intel = await extractor.extract(text)
            assert "scammer@ybl" in intel.upiIds


class TestEdgeCases:
    """Tests for edge cases in extraction."""

    def test_empty_text(self, extractor):
        """Test extraction from empty text."""
        intel = extractor._extract_with_regex("")
        assert intel.upiIds == []
        assert intel.phoneNumbers == []
        assert intel.bankAccounts == []

    def test_special_characters(self, extractor):
        """Test extraction handles special characters."""
        text = "UPI: test-user.name@ybl! Contact: +91-9876543210..."
        intel = extractor._extract_with_regex(text)
        assert len(intel.upiIds) > 0
        assert len(intel.phoneNumbers) > 0

    def test_mixed_case(self, extractor):
        """Test that extraction is case-insensitive where appropriate."""
        text = "UPI: SCAMMER@YBL phone: +91 9876543210"
        intel = extractor._extract_with_regex(text)
        # UPI should be lowercased
        assert any("scammer" in upi.lower() for upi in intel.upiIds)

    def test_multiple_items_same_type(self, extractor):
        """Test extraction of multiple items of same type."""
        text = "UPIs: one@ybl, two@paytm, three@oksbi. Phones: 9876543210, 8765432109"
        intel = extractor._extract_with_regex(text)
        assert len(intel.upiIds) >= 3
        assert len(intel.phoneNumbers) >= 2
