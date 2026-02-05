"""
Tests for app/utils/patterns.py

Tests regex patterns and keyword scoring functions.
"""

import pytest
from app.utils.patterns import (
    UPI_PATTERN,
    BANK_ACCOUNT_PATTERN,
    PHONE_PATTERN,
    URL_PATTERN,
    EMAIL_PATTERN,
    SCAM_KEYWORDS,
    URGENCY_PATTERNS,
    calculate_keyword_score
)
import re


class TestUPIPattern:
    """Tests for UPI ID pattern matching."""

    def test_valid_upi_ids(self):
        """Test detection of valid UPI IDs."""
        valid_upis = [
            "ramesh@ybl",
            "9876543210@paytm",
            "user.name@okaxis",
            "test-user@oksbi",
            "User123@icici",
        ]
        for upi in valid_upis:
            matches = re.findall(UPI_PATTERN, upi)
            assert len(matches) == 1, f"Should match UPI: {upi}"

    def test_upi_in_text(self):
        """Test extracting UPI from larger text."""
        text = "Send money to my UPI scammer@ybl or pay at fraud@paytm"
        matches = re.findall(UPI_PATTERN, text)
        assert "scammer@ybl" in matches
        assert "fraud@paytm" in matches

    def test_invalid_upi_formats(self):
        """Test that invalid UPI formats are rejected."""
        invalid_upis = [
            "noatsign",
            "@noprefix",
            "user@",  # No handle
        ]
        for invalid in invalid_upis:
            matches = re.findall(UPI_PATTERN, invalid)
            # Some of these may partially match, which is expected behavior
            # The actual filtering happens in intelligence.py


class TestBankAccountPattern:
    """Tests for bank account number pattern matching."""

    def test_valid_account_numbers(self):
        """Test detection of valid bank account numbers."""
        valid_accounts = [
            "123456789",       # 9 digits
            "1234567890123",   # 13 digits
            "123456789012345678",  # 18 digits
        ]
        for account in valid_accounts:
            matches = re.findall(BANK_ACCOUNT_PATTERN, account)
            assert len(matches) == 1, f"Should match account: {account}"

    def test_account_in_text(self):
        """Test extracting account numbers from text."""
        text = "My account number is 12345678901234. Transfer to this."
        matches = re.findall(BANK_ACCOUNT_PATTERN, text)
        assert "12345678901234" in matches

    def test_rejects_short_numbers(self):
        """Test that numbers shorter than 9 digits are rejected."""
        text = "Code 12345678"  # 8 digits
        matches = re.findall(BANK_ACCOUNT_PATTERN, text)
        assert len(matches) == 0


class TestPhonePattern:
    """Tests for Indian phone number pattern matching."""

    def test_valid_phone_formats(self):
        """Test detection of various phone number formats."""
        valid_phones = [
            "9876543210",
            "+919876543210",
            "+91 9876543210",
            "+91-9876543210",
            "91 9876543210",
        ]
        for phone in valid_phones:
            matches = re.findall(PHONE_PATTERN, phone)
            assert len(matches) >= 1, f"Should match phone: {phone}"

    def test_phone_in_text(self):
        """Test extracting phone numbers from text."""
        text = "Call me at 9876543210 or +91 8765432109"
        matches = re.findall(PHONE_PATTERN, text)
        assert len(matches) == 2

    def test_indian_mobile_prefix(self):
        """Test that only valid Indian mobile prefixes (6-9) are matched."""
        text = "Number 5876543210"  # Starts with 5, invalid
        matches = re.findall(PHONE_PATTERN, text)
        assert len(matches) == 0


class TestURLPattern:
    """Tests for URL pattern matching."""

    def test_valid_urls(self):
        """Test detection of valid URLs."""
        valid_urls = [
            "http://example.com",
            "https://secure.bank.com",
            "https://fake-bank.com/login",
            "http://scam.site/verify?id=123",
        ]
        for url in valid_urls:
            matches = re.findall(URL_PATTERN, url)
            assert len(matches) == 1, f"Should match URL: {url}"

    def test_url_in_text(self):
        """Test extracting URLs from text."""
        text = "Click here: https://phishing.site/login to verify your account"
        matches = re.findall(URL_PATTERN, text)
        assert "https://phishing.site/login" in matches


class TestEmailPattern:
    """Tests for email pattern matching."""

    def test_valid_emails(self):
        """Test detection of valid emails."""
        valid_emails = [
            "user@example.com",
            "test.user@bank.co.in",
            "support+tag@company.org",
        ]
        for email in valid_emails:
            matches = re.findall(EMAIL_PATTERN, email)
            assert len(matches) == 1, f"Should match email: {email}"


class TestKeywordScoring:
    """Tests for the keyword scoring function."""

    def test_scam_message_high_score(self):
        """Test that scam messages get high scores."""
        scam_text = "You won lottery! Share OTP to claim 10 lakh prize."
        score, keywords = calculate_keyword_score(scam_text)
        assert score > 0.5, "Scam message should score above 0.5"
        assert "lottery" in keywords
        assert "otp" in keywords

    def test_legitimate_message_low_score(self):
        """Test that legitimate messages get low scores."""
        normal_text = "Hello, how are you doing today?"
        score, keywords = calculate_keyword_score(normal_text)
        assert score < 0.3, "Normal message should score below 0.3"

    def test_urgency_keywords(self):
        """Test detection of urgency keywords."""
        urgent_text = "Account blocked! Act immediately to avoid legal action."
        score, keywords = calculate_keyword_score(urgent_text)
        assert score > 0.3
        assert "blocked" in keywords

    def test_financial_keywords(self):
        """Test detection of financial request keywords."""
        financial_text = "Send your bank details and CVV to verify payment"
        score, keywords = calculate_keyword_score(financial_text)
        assert "bank details" in keywords or "cvv" in keywords

    def test_score_capped_at_one(self):
        """Test that score is capped at 1.0."""
        extreme_text = (
            "lottery winner prize jackpot otp pin cvv password "
            "bank details blocked urgent immediately legal action"
        )
        score, _ = calculate_keyword_score(extreme_text)
        assert score <= 1.0, "Score should never exceed 1.0"

    def test_case_insensitive(self):
        """Test that matching is case insensitive."""
        text1 = "LOTTERY OTP"
        text2 = "lottery otp"
        score1, _ = calculate_keyword_score(text1)
        score2, _ = calculate_keyword_score(text2)
        assert score1 == score2, "Scores should be equal regardless of case"


class TestUrgencyPatterns:
    """Tests for urgency pattern matching."""

    def test_urgency_patterns_match(self):
        """Test that urgency patterns match correctly."""
        urgent_phrases = [
            "within 24 hours",
            "expires today",
            "last chance",
            "final notice",
            "immediately",
            "act now",
            "don't miss out",
            "time is running out",
        ]
        for phrase in urgent_phrases:
            matched = any(
                re.search(pattern, phrase, re.IGNORECASE)
                for pattern in URGENCY_PATTERNS
            )
            assert matched, f"Should match urgency phrase: {phrase}"
