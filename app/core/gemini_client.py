"""
Google Gemini AI Client

This file wraps the Google Gemini API to make it easy to use.
Think of it as a "translator" between our code and Google's AI.

WHAT IS GEMINI?
Gemini is Google's AI model (like ChatGPT but from Google).
It can understand text, analyze content, and generate responses.

WHY A WRAPPER?
Instead of writing complex API code everywhere, we create simple
functions like "analyze_for_scam()" and "generate_response()".
"""

import json
import re
import logging
import google.generativeai as genai
from typing import Dict, List, Optional

from app.config import settings

# Set up logging (so we can see what's happening)
logger = logging.getLogger(__name__)


class GeminiClient:
    """
    Client for interacting with Google Gemini AI.

    Usage:
        client = GeminiClient()
        result = await client.analyze_for_scam("You won lottery!")
        response = await client.generate_response(prompt, history, message)
    """

    def __init__(self):
        """
        Initialize the Gemini client with API key.

        This runs once when we create the client.
        It sets up the connection to Google's AI.
        """
        # Configure the API with our key
        genai.configure(api_key=settings.GEMINI_API_KEY)

        # Create the model instance
        # gemini-1.5-flash is fast and cheap - perfect for hackathons
        self.model = genai.GenerativeModel(settings.GEMINI_MODEL)

        logger.info(f"Gemini client initialized with model: {settings.GEMINI_MODEL}")

    async def analyze_for_scam(
        self,
        message: str,
        context: str = ""
    ) -> Dict:
        """
        Analyze a message to detect if it's a scam.

        Args:
            message: The message to analyze
            context: Optional conversation context

        Returns:
            Dictionary with:
            - is_scam: True/False
            - confidence: 0.0 to 1.0
            - scam_type: lottery/phishing/impersonation/etc.
            - indicators: List of red flags found
            - reasoning: Why we think it's a scam

        Example:
            >>> result = await client.analyze_for_scam("You won 10 lakh!")
            >>> print(result)
            {
                "is_scam": True,
                "confidence": 0.9,
                "scam_type": "lottery",
                "indicators": ["prize claim", "urgency"],
                "reasoning": "Classic lottery scam tactics"
            }
        """
        # Create the analysis prompt
        # We ask Gemini to respond in JSON format for easy parsing
        analysis_prompt = f"""Analyze this message for scam/fraud indicators.

Context (previous conversation): {context if context else "None"}

Message to analyze: {message}

You are a scam detection expert. Analyze for:
1. Lottery/Prize scams
2. Bank/UPI fraud
3. Impersonation (fake bank employee, govt official)
4. Investment scams (crypto, guaranteed returns)
5. KYC/Verification scams
6. Tech support scams
7. Phishing attempts

Respond in JSON format ONLY (no other text):
{{
    "is_scam": true or false,
    "confidence": 0.0 to 1.0,
    "scam_type": "lottery|phishing|impersonation|investment|kyc|tech_support|romance|other|none",
    "indicators": ["list", "of", "red", "flags"],
    "reasoning": "brief explanation"
}}"""

        try:
            # Call Gemini API
            response = self.model.generate_content(
                analysis_prompt,
                generation_config=genai.types.GenerationConfig(
                    temperature=0.1,  # Low temperature = more consistent/factual
                    max_output_tokens=500
                )
            )

            # Parse the JSON response
            return self._parse_json_response(response.text)

        except Exception as e:
            logger.error(f"Gemini analysis error: {e}")
            # Return safe defaults if API fails
            return {
                "is_scam": False,
                "confidence": 0.0,
                "scam_type": "unknown",
                "indicators": [],
                "reasoning": f"Analysis failed: {str(e)}"
            }

    async def generate_response(
        self,
        system_prompt: str,
        conversation_history: List[Dict[str, str]],
        scammer_message: str,
        temperature: float = 0.8
    ) -> str:
        """
        Generate a honeypot response to engage the scammer.

        Args:
            system_prompt: Instructions for how to respond (persona)
            conversation_history: Previous messages in the conversation
            scammer_message: The latest message from the scammer
            temperature: Creativity level (0.0=boring, 1.0=creative)

        Returns:
            A human-like response as the honeypot persona

        Example:
            >>> response = await client.generate_response(
            ...     system_prompt="You are Kamla Devi, 65 years old...",
            ...     conversation_history=[],
            ...     scammer_message="You won lottery!"
            ... )
            >>> print(response)
            "Arre wah! Lottery? Mujhe toh yaad nahi maine koi ticket liya tha..."
        """
        # Build the full prompt with conversation context
        full_prompt = self._build_conversation_prompt(
            system_prompt,
            conversation_history,
            scammer_message
        )

        try:
            # Call Gemini API
            response = self.model.generate_content(
                full_prompt,
                generation_config=genai.types.GenerationConfig(
                    temperature=temperature,  # Higher = more creative
                    max_output_tokens=300  # Keep responses short and natural
                )
            )

            # Clean up the response
            reply = response.text.strip()

            # Remove any quotation marks at start/end
            reply = reply.strip('"\'')

            return reply

        except Exception as e:
            logger.error(f"Gemini response generation error: {e}")
            # Return a generic response if API fails
            return "Haan ji? Samajh nahi aaya, thoda aur batao beta..."

    async def extract_intelligence(self, text: str) -> Dict:
        """
        Use AI to extract intelligence that regex might miss.

        Sometimes scammers write numbers in words or use tricks
        that regex can't catch. AI can understand context.

        Args:
            text: Text to extract information from

        Returns:
            Dictionary with extracted data

        Example:
            >>> result = await client.extract_intelligence(
            ...     "Send money to my Paytm nine eight seven six..."
            ... )
            >>> print(result)
            {"phone_numbers": ["9876543210"]}
        """
        extraction_prompt = f"""Extract any sensitive information from this text.

Text: {text}

Look for (even if written in words or obfuscated):
- Bank account numbers
- UPI IDs (like name@ybl, phone@paytm)
- Phone numbers (especially Indian +91 format)
- URLs or links
- Email addresses
- Names of people or organizations
- Payment app references (Paytm, PhonePe, GPay)

Respond in JSON format ONLY:
{{
    "bank_accounts": [],
    "upi_ids": [],
    "phone_numbers": [],
    "urls": [],
    "emails": [],
    "names": [],
    "payment_apps": []
}}"""

        try:
            response = self.model.generate_content(
                extraction_prompt,
                generation_config=genai.types.GenerationConfig(
                    temperature=0.1,
                    max_output_tokens=300
                )
            )
            return self._parse_json_response(response.text)

        except Exception as e:
            logger.error(f"Gemini extraction error: {e}")
            return {}

    def _build_conversation_prompt(
        self,
        system_prompt: str,
        history: List[Dict[str, str]],
        current_message: str
    ) -> str:
        """
        Build the full prompt including conversation history.

        We include the last 10 messages so Gemini understands context
        but don't include too many (to save tokens/cost).
        """
        parts = [system_prompt, "\n\n--- CONVERSATION ---\n"]

        # Add last 10 messages from history
        for msg in history[-10:]:
            role = "Scammer" if msg.get("role") == "scammer" else "You"
            content = msg.get("content", "")
            parts.append(f"{role}: {content}")

        # Add the current message
        parts.append(f"\nScammer: {current_message}")
        parts.append("\nYour response (stay in character, 1-2 sentences):")

        return "\n".join(parts)

    def _parse_json_response(self, text: str) -> Dict:
        """
        Parse JSON from Gemini's response.

        Gemini sometimes wraps JSON in markdown code blocks,
        so we need to handle that.
        """
        # Try to extract JSON from code blocks
        json_match = re.search(r'```(?:json)?\s*(.*?)\s*```', text, re.DOTALL)
        if json_match:
            text = json_match.group(1)

        # Try to parse the JSON
        try:
            return json.loads(text.strip())
        except json.JSONDecodeError:
            logger.warning(f"Failed to parse JSON: {text[:200]}...")
            return {}


# Create a singleton instance
# This way we only create one client and reuse it
gemini_client = GeminiClient()
