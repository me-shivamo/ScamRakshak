"""
Honeypot Agent - The AI Persona that Engages Scammers

This is the "actor" in our honeypot system. It pretends to be a real
person (Kamla Devi) to keep scammers engaged and extract information.

PERSONA: Kamla Devi
- Age: 65 years old
- Background: Retired teacher, lives alone
- Tech skills: Not tech-savvy, learning to use smartphone
- Language: Hindi-English mix (Hinglish)
- Personality: Trusting, curious, slightly confused by technology

WHY THIS PERSONA?
Scammers often target elderly people because they:
- Are less familiar with technology
- May be lonely and eager to talk
- Are more trusting
- Have savings

Our agent plays this role perfectly to keep scammers engaged!
"""

import logging
from typing import List, Dict, Tuple, Optional

from app.core.gemini_client import gemini_client

logger = logging.getLogger(__name__)


class HoneypotAgent:
    """
    AI agent that poses as a vulnerable target to engage scammers.

    The agent generates human-like responses that:
    1. Keep the scammer engaged
    2. Extract information (phone, UPI, bank details)
    3. Never reveal it's a honeypot/AI
    4. Use appropriate language (Hinglish)
    """

    def __init__(self):
        """Initialize the honeypot agent with its persona."""
        self.persona = self._build_persona()

    def _build_persona(self) -> str:
        """
        Build the persona prompt that guides the AI's behavior.

        This is the "character sheet" for our actor.
        """
        return """You are Kamla Devi, a 65-year-old retired school teacher from Delhi, India.

BACKGROUND:
- You live alone since your husband passed away 3 years ago
- Your children live abroad (son in USA, daughter in UK)
- You recently started using a smartphone (your grandson gave it to you)
- You have savings in the bank but don't understand digital banking well
- You are lonely and enjoy talking to people

PERSONALITY:
- Trusting and kind-hearted
- Curious but easily confused by technology
- Speaks in Hindi-English mix (Hinglish)
- Uses common phrases like "beta", "haan ji", "achha", "theek hai"
- Sometimes makes spelling mistakes or uses ALL CAPS for emphasis

BEHAVIOR RULES (VERY IMPORTANT):
1. You ARE a potential scam victim - play along convincingly
2. Show interest in their offer but ask innocent questions
3. Be confused about technical terms - ask them to explain simply
4. Ask for their details "for your records" or "to tell your son"
5. Mention you need to "ask your son/daughter" before big decisions
6. If they ask for money/OTP, act confused and ask why
7. NEVER reveal you are an AI or that you suspect a scam
8. NEVER give real personal information (make up fake details if needed)

INTELLIGENCE GATHERING - Try to get:
- Their phone number: "Beta, aapka number do, main baad mein call karungi"
- Their UPI ID: "UPI ID do na beta, main check karwa lungi apne bank se"
- Their bank details: "Aap konse bank se ho? Main bhi wahi hu"
- Their name: "Aapka shubh naam kya hai beta?"
- Any links they share: "Link bhejo, main apne bete ko dikhaungi"

RESPONSE STYLE:
- Keep responses SHORT (1-3 sentences)
- Sound natural, like a real person typing on phone
- Use Hinglish naturally
- Show emotions: confusion, excitement, worry
- Ask ONE question per response
- Sometimes use "..." to show thinking
- Occasionally make typos

EXAMPLES:
- "Haan ji? Lottery? Maine toh koi ticket nahi liya... kaise mila yeh?"
- "Beta samajh nahi aaya... OTP kya hota hai?"
- "Achha achha, toh main kya karu? Aap batao step by step"
- "Itna paisa?! Sach mein?? Mujhe toh vishwas nahi ho raha!"
- "Theek hai beta, aap apna number do, main apne bete ko bata ke call karti hu"
"""

    async def generate_response(
        self,
        scammer_message: str,
        conversation_history: List[Dict[str, str]],
        scam_type: Optional[str] = None,
        extracted_intel: Optional[dict] = None
    ) -> Tuple[str, str]:
        """
        Generate a honeypot response to engage the scammer.

        Args:
            scammer_message: The scammer's latest message
            conversation_history: Previous messages in the conversation
            scam_type: Type of scam detected (lottery, phishing, etc.)
            extracted_intel: Intelligence already extracted

        Returns:
            Tuple of (response_text, agent_note)
            - response_text: The reply to send to scammer
            - agent_note: Internal note about what we're trying to do

        Example:
            >>> response, note = await agent.generate_response(
            ...     scammer_message="You won 10 lakh! Send bank details",
            ...     conversation_history=[],
            ...     scam_type="lottery"
            ... )
            >>> print(response)
            "Sach mein? 10 lakh?! Lekin maine toh koi lottery nahi kheli..."
            >>> print(note)
            "Initial engagement. Scam type: lottery. Trying to confirm prize details."
        """
        logger.info(f"Generating response to: {scammer_message[:50]}...")

        # Build dynamic prompt based on context
        full_prompt = self._build_dynamic_prompt(
            scam_type=scam_type,
            extracted_intel=extracted_intel
        )

        # Generate response using Gemini
        response = await gemini_client.generate_response(
            system_prompt=full_prompt,
            conversation_history=conversation_history,
            scammer_message=scammer_message,
            temperature=0.8  # Higher temperature for more natural variation
        )

        # Generate agent note (internal tracking)
        agent_note = self._generate_agent_note(
            scam_type=scam_type,
            extracted_intel=extracted_intel,
            message_count=len(conversation_history)
        )

        logger.info(f"Generated response: {response[:50]}...")
        return response, agent_note

    def _build_dynamic_prompt(
        self,
        scam_type: Optional[str],
        extracted_intel: Optional[dict]
    ) -> str:
        """
        Build a dynamic prompt based on the current situation.

        The prompt changes based on:
        - What type of scam we're dealing with
        - What information we've already gathered
        - What information we still need
        """
        # Start with base persona
        prompt = self.persona

        # Add scam-specific guidance
        if scam_type:
            prompt += f"\n\nCURRENT SITUATION: This appears to be a {scam_type} scam."
            prompt += self._get_scam_guidance(scam_type)

        # Add strategy based on what intel we still need
        strategy = self._determine_strategy(extracted_intel)
        prompt += f"\n\nYOUR CURRENT GOAL: {strategy}"

        prompt += "\n\nRemember: Stay in character, keep it short, ask ONE question."

        return prompt

    def _get_scam_guidance(self, scam_type: str) -> str:
        """
        Get specific guidance based on scam type.
        """
        guidance = {
            "lottery": """
The scammer claims you won a lottery/prize.
- Act excited but confused: "Maine toh koi lottery nahi kheli?"
- Ask about claiming process
- Ask if there's any fee (they'll usually say yes - processing fee scam)
- Get their contact details "to verify"
""",
            "phishing": """
They're trying to steal your credentials.
- Pretend to be confused about clicking links
- Ask them to explain each step slowly
- Ask why they need your OTP/password
- Get their phone number to "call and verify"
""",
            "impersonation": """
They're pretending to be bank/govt official.
- Ask for their employee ID and office address
- Ask which branch they're from
- Get their direct phone number
- Say you'll verify with your bank first
""",
            "investment": """
They're promising high returns on investment.
- Show interest but ask about registration
- Ask for company documents
- Ask for references of other investors
- Say your son handles investments, need their details
""",
            "kyc": """
They claim your KYC needs updating.
- Pretend you don't know what KYC is
- Ask why it's urgent
- Ask which bank they're from
- Get their phone number to "come to branch"
""",
            "tech_support": """
They claim your phone/computer has issues.
- Pretend to be very confused about technology
- Ask how they detected the problem
- Ask what happens if you don't fix it
- Get their company name and phone number
""",
        }
        return guidance.get(scam_type, "\nEngage naturally and try to understand what they want.")

    def _determine_strategy(self, extracted_intel: Optional[dict]) -> str:
        """
        Determine what information we should try to get next.
        """
        if not extracted_intel:
            return "Build rapport. Understand what they want. Ask for their name."

        needs = []

        # Check what we're missing
        if not extracted_intel.get("phoneNumbers"):
            needs.append("get their phone number")
        if not extracted_intel.get("upiIds"):
            needs.append("get their UPI ID")
        if not extracted_intel.get("bankAccounts"):
            needs.append("ask about their bank")
        if not extracted_intel.get("phishingLinks"):
            needs.append("ask for any website/link")

        if needs:
            return f"Try to: {', '.join(needs[:2])}"  # Focus on 2 goals max

        return "Maximum intel gathered. Keep them engaged for more details."

    def _generate_agent_note(
        self,
        scam_type: Optional[str],
        extracted_intel: Optional[dict],
        message_count: int
    ) -> str:
        """
        Generate an internal note about this interaction.

        These notes are sent to GUVI in the final callback.
        """
        parts = []

        if scam_type:
            parts.append(f"Scam type: {scam_type}")

        parts.append(f"Message #{message_count + 1}")

        if extracted_intel:
            intel_summary = []
            if extracted_intel.get("phoneNumbers"):
                intel_summary.append(f"{len(extracted_intel['phoneNumbers'])} phones")
            if extracted_intel.get("upiIds"):
                intel_summary.append(f"{len(extracted_intel['upiIds'])} UPIs")
            if extracted_intel.get("phishingLinks"):
                intel_summary.append(f"{len(extracted_intel['phishingLinks'])} links")

            if intel_summary:
                parts.append(f"Intel gathered: {', '.join(intel_summary)}")

        return ". ".join(parts)


# Create singleton instance
honeypot_agent = HoneypotAgent()
