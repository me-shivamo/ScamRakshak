"""
Tests for app/core/scam_detector.py

Tests the scam detection module.
"""

import pytest
from unittest.mock import AsyncMock, patch
from app.core.scam_detector import ScamDetector


@pytest.fixture
def detector():
    """Create a ScamDetector instance."""
    return ScamDetector()


class TestPatternAnalysis:
    """Tests for pattern-based scam detection."""

    def test_high_score_for_scam_message(self, detector):
        """Test that obvious scam messages get high pattern scores."""
        scam_text = "You won lottery! Share OTP immediately to claim 10 lakh prize!"
        score, indicators = detector._analyze_patterns(scam_text)

        assert score > 0.5, "Scam message should score above 0.5"
        assert len(indicators) > 0, "Should have indicators"

    def test_low_score_for_normal_message(self, detector):
        """Test that normal messages get low pattern scores."""
        normal_text = "Hello, how are you today? Nice weather we're having."
        score, indicators = detector._analyze_patterns(normal_text)

        assert score < 0.3, "Normal message should score below 0.3"

    def test_urgency_detection(self, detector):
        """Test that urgency patterns are detected."""
        urgent_text = "Act now within 24 hours or your account will be blocked!"
        score, indicators = detector._analyze_patterns(urgent_text)

        assert "Urgency language detected" in indicators

    def test_financial_request_detection(self, detector):
        """Test detection of financial request patterns."""
        test_cases = [
            ("Send money to claim prize", "Money request detected"),
            ("Share your bank details now", "Bank info request"),
            ("Send OTP to verify", "Credential request"),  # Pattern: (share|send|give)\s*(otp|pin|password)
            ("Transfer 5000 rupees immediately", "Transfer request detected"),
        ]

        for text, expected_indicator in test_cases:
            score, indicators = detector._analyze_patterns(text)
            assert expected_indicator in indicators, f"Should detect: {expected_indicator} in '{text}', got {indicators}"

    def test_score_capped_at_one(self, detector):
        """Test that score never exceeds 1.0."""
        extreme_text = (
            "Lottery winner! Won jackpot prize! Share OTP PIN CVV password "
            "bank details urgently immediately! Legal action blocked suspended "
            "transfer money send payment processing fee advance payment"
        )
        score, _ = detector._analyze_patterns(extreme_text)

        assert score <= 1.0, "Score should never exceed 1.0"

    def test_keyword_indicators(self, detector):
        """Test that found keywords are reported as indicators."""
        text = "lottery otp blocked"
        score, indicators = detector._analyze_patterns(text)

        keyword_indicators = [i for i in indicators if i.startswith("Keyword:")]
        assert len(keyword_indicators) > 0


class TestContextBuilding:
    """Tests for conversation context building."""

    def test_empty_history(self, detector):
        """Test context building with no history."""
        context = detector._build_context(None)
        assert context == ""

        context = detector._build_context([])
        assert context == ""

    def test_context_from_history(self, detector):
        """Test context building from conversation history."""
        history = [
            {"role": "scammer", "content": "You won lottery!"},
            {"role": "agent", "content": "Really? Tell me more."},
            {"role": "scammer", "content": "Send OTP to claim."},
        ]
        context = detector._build_context(history)

        assert "scammer:" in context
        assert "agent:" in context
        assert "lottery" in context.lower()

    def test_context_truncates_long_messages(self, detector):
        """Test that long messages are truncated in context."""
        long_message = "a" * 200  # 200 chars
        history = [{"role": "scammer", "content": long_message}]
        context = detector._build_context(history)

        # Should be truncated to 100 chars max per message
        assert len(context) < 200

    def test_context_uses_recent_history(self, detector):
        """Test that only last 5 messages are used."""
        history = [
            {"role": "scammer", "content": f"Message {i}"}
            for i in range(10)
        ]
        context = detector._build_context(history)

        # Should only contain messages 5-9
        assert "Message 5" in context
        assert "Message 9" in context
        assert "Message 0" not in context


class TestQuickCheck:
    """Tests for the quick_check method."""

    def test_quick_scam_detection(self, detector):
        """Test quick check identifies potential scams."""
        scam_text = "You won lottery! Send OTP now!"
        might_be_scam, score = detector.quick_check(scam_text)

        assert might_be_scam is True
        assert score > 0.3

    def test_quick_normal_detection(self, detector):
        """Test quick check passes normal messages."""
        normal_text = "Hello, how can I help you?"
        might_be_scam, score = detector.quick_check(normal_text)

        assert might_be_scam is False
        assert score < 0.3


class TestAsyncDetection:
    """Tests for async detection with mocked AI."""

    @pytest.mark.asyncio
    async def test_detect_scam_message(self, detector):
        """Test full detection of scam message."""
        scam_text = "You won 10 lakh lottery! Share OTP to claim."

        with patch("app.core.scam_detector.gemini_client") as mock_gemini:
            mock_gemini.analyze_for_scam = AsyncMock(return_value={
                "confidence": 0.9,
                "scam_type": "lottery_scam",
                "indicators": ["lottery", "prize claim"]
            })

            is_scam, confidence, scam_type, indicators = await detector.detect(scam_text)

            assert is_scam is True
            assert confidence > 0.5
            assert scam_type == "lottery_scam"

    @pytest.mark.asyncio
    async def test_detect_normal_message(self, detector):
        """Test full detection of normal message."""
        normal_text = "Hello, I wanted to ask about your services."

        with patch("app.core.scam_detector.gemini_client") as mock_gemini:
            mock_gemini.analyze_for_scam = AsyncMock(return_value={
                "confidence": 0.1,
                "scam_type": "none",
                "indicators": []
            })

            is_scam, confidence, scam_type, indicators = await detector.detect(normal_text)

            assert is_scam is False
            assert confidence < 0.4

    @pytest.mark.asyncio
    async def test_combined_confidence_calculation(self, detector):
        """Test that combined confidence uses correct weights."""
        text = "Some text"

        with patch("app.core.scam_detector.gemini_client") as mock_gemini:
            mock_gemini.analyze_for_scam = AsyncMock(return_value={
                "confidence": 0.8,
                "scam_type": "test",
                "indicators": []
            })

            # Mock pattern score to return 0.5
            with patch.object(detector, "_analyze_patterns", return_value=(0.5, [])):
                is_scam, confidence, _, _ = await detector.detect(text)

                # Expected: (0.5 * 0.3) + (0.8 * 0.7) = 0.15 + 0.56 = 0.71
                expected = (0.5 * 0.3) + (0.8 * 0.7)
                assert abs(confidence - expected) < 0.01

    @pytest.mark.asyncio
    async def test_existing_confidence_factor(self, detector):
        """Test that existing confidence influences detection."""
        text = "Normal looking message"

        with patch("app.core.scam_detector.gemini_client") as mock_gemini:
            mock_gemini.analyze_for_scam = AsyncMock(return_value={
                "confidence": 0.2,
                "scam_type": "none",
                "indicators": []
            })

            # With high existing confidence, should maintain suspicion
            _, confidence, _, _ = await detector.detect(
                text,
                existing_confidence=0.9
            )

            # Should factor in existing confidence (0.9 * 0.85 = 0.765)
            assert confidence >= 0.7

    @pytest.mark.asyncio
    async def test_detection_with_conversation_history(self, detector):
        """Test detection uses conversation history."""
        text = "Send the OTP now"
        history = [
            {"role": "scammer", "content": "You won lottery!"},
            {"role": "agent", "content": "Really?"},
        ]

        with patch("app.core.scam_detector.gemini_client") as mock_gemini:
            mock_gemini.analyze_for_scam = AsyncMock(return_value={
                "confidence": 0.85,
                "scam_type": "lottery_scam",
                "indicators": ["otp request"]
            })

            is_scam, _, _, _ = await detector.detect(text, conversation_history=history)

            # Verify AI was called
            mock_gemini.analyze_for_scam.assert_called_once()

    @pytest.mark.asyncio
    async def test_indicators_combined(self, detector):
        """Test that indicators from both sources are combined."""
        text = "Lottery OTP urgent"

        with patch("app.core.scam_detector.gemini_client") as mock_gemini:
            mock_gemini.analyze_for_scam = AsyncMock(return_value={
                "confidence": 0.8,
                "scam_type": "lottery_scam",
                "indicators": ["AI indicator 1", "AI indicator 2"]
            })

            _, _, _, indicators = await detector.detect(text)

            # Should have both pattern and AI indicators
            assert len(indicators) > 2  # Has pattern + AI indicators


class TestEdgeCases:
    """Tests for edge cases in scam detection."""

    def test_empty_message(self, detector):
        """Test handling of empty message."""
        score, indicators = detector._analyze_patterns("")
        assert score == 0.0
        assert len(indicators) == 0

    def test_special_characters_only(self, detector):
        """Test handling of special characters."""
        score, _ = detector._analyze_patterns("!@#$%^&*()")
        assert score == 0.0

    def test_very_long_message(self, detector):
        """Test handling of very long message."""
        long_text = "hello " * 1000  # Very long message
        score, indicators = detector._analyze_patterns(long_text)
        # Should complete without error
        assert score >= 0

    def test_unicode_message(self, detector):
        """Test handling of unicode/Hindi text."""
        hindi_text = "आपको लॉटरी मिली है! OTP भेजें।"
        score, indicators = detector._analyze_patterns(hindi_text)
        # Should detect OTP keyword
        assert "otp" in [i.lower() for i in indicators if "Keyword" in i] or score > 0
