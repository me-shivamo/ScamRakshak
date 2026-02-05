"""
Scam Detection Module

This module detects if a message is a scam using TWO methods:
1. Pattern Matching (fast) - Look for scam keywords
2. AI Analysis (smart) - Understand context and tricks

WHY TWO METHODS?
- Pattern matching is fast but can be tricked ("l0ttery" instead of "lottery")
- AI is smart but slow and expensive
- Combined: Fast first check, AI for confirmation

SCORING:
- Pattern score: 0.0 to 1.0 (based on keywords)
- AI confidence: 0.0 to 1.0 (Gemini's analysis)
- Combined: (pattern * 0.3) + (AI * 0.7)
- If combined > 0.5 → Likely a scam

Example:
    "You won 10 lakh lottery! Send OTP now!"
    - Pattern score: 0.85 (lottery, won, lakh, otp)
    - AI confidence: 0.95
    - Combined: (0.85 * 0.3) + (0.95 * 0.7) = 0.92
    - Result: SCAM DETECTED
"""

import re
import logging
from typing import Dict, List, Tuple, Optional

from app.core.gemini_client import gemini_client
from app.utils.patterns import (
    SCAM_KEYWORDS,
    URGENCY_PATTERNS,
    calculate_keyword_score
)

logger = logging.getLogger(__name__)


class ScamDetector:
    """
    Hybrid scam detection combining pattern matching and AI analysis.

    Usage:
        detector = ScamDetector()
        is_scam, confidence, scam_type, indicators = await detector.detect(
            message="You won lottery!",
            conversation_history=[]
        )
    """

    def __init__(self):
        """Initialize the scam detector."""
        self.scam_keywords = SCAM_KEYWORDS
        self.urgency_patterns = URGENCY_PATTERNS

    async def detect(
        self,
        message: str,
        conversation_history: Optional[List[Dict]] = None,
        existing_confidence: float = 0.0
    ) -> Tuple[bool, float, str, List[str]]:
        """
        Detect if a message is a scam.

        Args:
            message: The message to analyze
            conversation_history: Previous messages (for context)
            existing_confidence: Confidence from previous detections in this conversation

        Returns:
            Tuple of:
            - is_scam (bool): True if scam detected
            - confidence (float): How confident we are (0.0-1.0)
            - scam_type (str): Type of scam detected
            - indicators (list): Red flags found

        Example:
            >>> is_scam, confidence, scam_type, indicators = await detector.detect(
            ...     "Your bank account will be blocked. Share OTP to verify."
            ... )
            >>> print(is_scam, confidence, scam_type)
            True 0.89 "phishing"
            >>> print(indicators)
            ["blocked", "otp", "urgency language"]
        """
        logger.info(f"Analyzing message: {message[:50]}...")

        # Step 1: Quick pattern-based detection
        pattern_score, pattern_indicators = self._analyze_patterns(message)
        logger.debug(f"Pattern score: {pattern_score}, indicators: {pattern_indicators}")

        # Step 2: AI-based analysis (using Gemini)
        context = self._build_context(conversation_history)
        ai_analysis = await gemini_client.analyze_for_scam(message, context)

        ai_confidence = ai_analysis.get("confidence", 0.0)
        ai_scam_type = ai_analysis.get("scam_type", "unknown")
        ai_indicators = ai_analysis.get("indicators", [])

        # Step 3: Combine scores
        # Pattern matching: 30% weight (fast but basic)
        # AI analysis: 70% weight (smart but slower)
        combined_confidence = (pattern_score * 0.3) + (ai_confidence * 0.7)

        # Factor in existing confidence from conversation history
        # This helps: if previous messages were scammy, we're more suspicious
        if existing_confidence > 0:
            combined_confidence = max(combined_confidence, existing_confidence * 0.85)

        # Step 4: Determine final result
        is_scam = combined_confidence > 0.4  # Threshold: 40% confidence

        # Combine all indicators (remove duplicates)
        all_indicators = list(set(pattern_indicators + ai_indicators))

        # Log the result
        logger.info(
            f"Detection result: is_scam={is_scam}, "
            f"confidence={combined_confidence:.2f}, "
            f"type={ai_scam_type}"
        )

        return is_scam, combined_confidence, ai_scam_type, all_indicators

    def _analyze_patterns(self, message: str) -> Tuple[float, List[str]]:
        """
        Fast pattern-based scam detection.

        This is the first line of defense - quick and cheap.
        Looks for:
        - Scam keywords (lottery, otp, blocked, etc.)
        - Urgency patterns (within 24 hours, act now, etc.)
        - Financial request patterns (send money, bank details, etc.)

        Args:
            message: Text to analyze

        Returns:
            (score, indicators): Score 0.0-1.0 and list of red flags
        """
        message_lower = message.lower()
        indicators = []
        score = 0.0

        # Check scam keywords (using pre-defined weights)
        keyword_score, found_keywords = calculate_keyword_score(message)
        score += keyword_score
        indicators.extend([f"Keyword: {kw}" for kw in found_keywords])

        # Check urgency patterns
        for pattern in self.urgency_patterns:
            if re.search(pattern, message_lower, re.IGNORECASE):
                score += 0.15
                indicators.append("Urgency language detected")
                break  # Count urgency only once

        # Check for financial request patterns
        financial_patterns = [
            (r'send\s+(money|payment|amount)', "Money request detected"),
            (r'(bank|account)\s*(details|number|info)', "Bank info request"),
            (r'(share|send|give)\s*(otp|pin|password)', "Credential request"),
            (r'(transfer|deposit)\s*\d+', "Transfer request detected"),
        ]

        for pattern, indicator in financial_patterns:
            if re.search(pattern, message_lower):
                score += 0.2
                indicators.append(indicator)

        # Cap score at 1.0
        return min(score, 1.0), indicators

    def _build_context(self, history: Optional[List[Dict]]) -> str:
        """
        Build context string from conversation history.

        This helps AI understand the full conversation, not just one message.
        """
        if not history:
            return ""

        # Take last 5 messages for context
        recent = history[-5:]
        context_parts = []

        for msg in recent:
            role = msg.get("role", "unknown")
            content = msg.get("content", "")[:100]  # Truncate long messages
            context_parts.append(f"{role}: {content}")

        return " | ".join(context_parts)

    def quick_check(self, message: str) -> Tuple[bool, float]:
        """
        Ultra-fast scam check using only pattern matching.

        Use this when you need a quick answer without AI.
        Less accurate but very fast (no API call).

        Args:
            message: Text to check

        Returns:
            (might_be_scam, score): Quick assessment
        """
        score, _ = self._analyze_patterns(message)
        return score > 0.3, score


# Create singleton instance
scam_detector = ScamDetector()
