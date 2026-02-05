"""
OpenAI ChatGPT Client

This file wraps the OpenAI API to make it easy to use.
Think of it as a "translator" between our code and OpenAI's AI.

WHAT IS ChatGPT?
ChatGPT is OpenAI's AI model - fast, reliable, and powerful.
It can understand text, analyze content, and generate responses.

WHY A WRAPPER?
Instead of writing complex API code everywhere, we create simple
functions like "analyze_for_scam()" and "generate_response()".
"""

import json
import re
import logging
from openai import AsyncOpenAI
from typing import Dict, List, Optional

from app.config import settings

# Set up logging (so we can see what's happening)
logger = logging.getLogger(__name__)


class GeminiClient:
    """
    Client for interacting with OpenAI ChatGPT.

    Note: Class name kept as GeminiClient for backward compatibility
    with existing imports throughout the codebase.

    Usage:
        client = GeminiClient()
        result = await client.analyze_for_scam("You won lottery!")
        response = await client.generate_response(prompt, history, message)
    """

    def __init__(self):
        """
        Initialize the OpenAI client with API key.

        This runs once when we create the client.
        It sets up the connection to OpenAI's AI.
        """
        # Create the async OpenAI client
        self.client = AsyncOpenAI(api_key=settings.OPENAI_API_KEY)

        # Store the model name
        self.model = settings.OPENAI_MODEL

        logger.info(f"OpenAI client initialized with model: {self.model}")

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
            # Call OpenAI API
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a scam detection expert. Always respond with valid JSON only."},
                    {"role": "user", "content": analysis_prompt}
                ],
                temperature=0.1,  # Low temperature = more consistent/factual
                max_tokens=1000
            )

            # Parse the JSON response
            return self._parse_json_response(response.choices[0].message.content)

        except Exception as e:
            logger.error(f"OpenAI analysis error: {e}")
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
        # Build messages for ChatGPT
        messages = [{"role": "system", "content": system_prompt}]

        # Add conversation history (last 10 messages)
        for msg in conversation_history[-10:]:
            role = "assistant" if msg.get("role") != "scammer" else "user"
            content = msg.get("content", "")
            messages.append({"role": role, "content": content})

        # Add the current scammer message
        messages.append({"role": "user", "content": scammer_message})

        try:
            # Call OpenAI API
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=temperature,  # Higher = more creative
                max_tokens=300  # Keep responses short and natural
            )

            # Clean up the response
            reply = response.choices[0].message.content.strip()

            # Remove any quotation marks at start/end
            reply = reply.strip('"\'')

            return reply

        except Exception as e:
            logger.error(f"OpenAI response generation error: {e}")
            # Return a generic response if API fails
            return "Error occurred while generating response. Please try again later."

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
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a data extraction expert. Always respond with valid JSON only."},
                    {"role": "user", "content": extraction_prompt}
                ],
                temperature=0.1,
                max_tokens=300
            )
            return self._parse_json_response(response.choices[0].message.content)

        except Exception as e:
            logger.error(f"OpenAI extraction error: {e}")
            return {}

    async def extract_intelligence_from_conversation(
        self,
        conversation_history: List[Dict[str, str]]
    ) -> Dict:
        """
        Use AI to extract ALL intelligence from the entire conversation.

        This analyzes the full conversation to extract:
        - Bank account numbers (even obfuscated or written in words)
        - UPI IDs (all formats like name@ybl, phone@paytm)
        - Phone numbers (Indian format, even as words)
        - Phishing URLs/links
        - Suspicious keywords indicating scam type

        Args:
            conversation_history: List of messages with 'role' and 'content' keys

        Returns:
            Dictionary matching ExtractedIntelligence schema:
            {
                "bankAccounts": [],
                "upiIds": [],
                "phoneNumbers": [],
                "phishingLinks": [],
                "suspiciousKeywords": []
            }
        """
        # Build conversation text for analysis
        conversation_text = "\n".join([
            f"{msg.get('role', 'unknown').upper()}: {msg.get('content', '')}"
            for msg in conversation_history
        ])

        extraction_prompt = f"""You are an expert intelligence extractor for scam detection. Analyze this entire conversation and extract ALL sensitive information.

CONVERSATION:
{conversation_text}

EXTRACT THE FOLLOWING (be thorough, check all messages):

1. **Bank Account Numbers**: Any 9-18 digit numbers that could be bank accounts. Even if written in words like "one two three four..." convert them to digits.

2. **UPI IDs**: Any UPI payment addresses in format username@bankhandle. Common handles: ybl, paytm, okaxis, oksbi, okicici, okhdfcbank, apl, upi, phonepe, gpay, etc.

3. **Phone Numbers**: Indian phone numbers (10 digits starting with 6-9). Handle:
   - Standard format: 9876543210
   - With country code: +91 9876543210, 91-9876543210
   - Written in words: "nine eight seven six five four three two one zero"
   - Spaced/formatted: "98765 43210", "9876-543-210"

4. **Phishing Links**: Any URLs or links, especially suspicious ones (shortened URLs, fake bank sites, etc.)

5. **Suspicious Keywords**: Key scam-related words/phrases found:
   - lottery, winner, prize, jackpot
   - urgent, immediately, within 24 hours
   - blocked, suspended, verify, update
   - otp, cvv, pin, password
   - processing fee, advance payment, registration fee
   - guaranteed returns, double money, investment
   - kyc, link aadhaar, pan card

Respond in JSON format ONLY (no other text):
{{
    "bankAccounts": ["list of account numbers as strings"],
    "upiIds": ["list of UPI IDs"],
    "phoneNumbers": ["list of 10-digit phone numbers"],
    "phishingLinks": ["list of URLs"],
    "suspiciousKeywords": ["list of scam keywords found"]
}}

IMPORTANT:
- Return empty arrays [] if nothing found for a category
- Normalize phone numbers to 10 digits (remove +91, spaces, dashes)
- Convert numbers written in words to digits
- Include ALL instances found across the entire conversation"""

        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are an expert scam intelligence extractor. Extract ALL sensitive information from conversations. Always respond with valid JSON only."
                    },
                    {"role": "user", "content": extraction_prompt}
                ],
                temperature=0.1,
                max_tokens=1000
            )

            result = self._parse_json_response(response.choices[0].message.content)

            # Ensure all required keys exist with proper format
            return {
                "bankAccounts": result.get("bankAccounts", []),
                "upiIds": result.get("upiIds", []),
                "phoneNumbers": result.get("phoneNumbers", []),
                "phishingLinks": result.get("phishingLinks", []),
                "suspiciousKeywords": result.get("suspiciousKeywords", [])
            }

        except Exception as e:
            logger.error(f"OpenAI conversation extraction error: {e}")
            return {
                "bankAccounts": [],
                "upiIds": [],
                "phoneNumbers": [],
                "phishingLinks": [],
                "suspiciousKeywords": []
            }

    def _build_conversation_prompt(
        self,
        system_prompt: str,
        history: List[Dict[str, str]],
        current_message: str
    ) -> str:
        """
        Build the full prompt including conversation history.

        We include the last 10 messages so AI understands context
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
        Parse JSON from OpenAI's response.

        OpenAI sometimes wraps JSON in markdown code blocks,
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
