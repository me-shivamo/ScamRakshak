"""
Regex Patterns and Keywords for Scam Detection

This file contains:
1. REGEX PATTERNS - To extract specific data (phone numbers, UPI IDs, etc.)
2. SCAM KEYWORDS - Words commonly used in scams (with weights)
3. URGENCY PATTERNS - Phrases that create false urgency

WHAT IS REGEX?
Regex is like a smart search. Instead of searching for exact text,
you describe a PATTERN and it finds all matches.

Example: "Find all phone numbers" = find any 10 digits in a row
"""

# ============================================================
# REGEX PATTERNS FOR EXTRACTION
# ============================================================

# UPI ID Pattern
# What it matches: name@bank, phone@paytm, user.name@ybl
# Breaking it down:
#   [a-zA-Z0-9._-]+  = One or more letters, numbers, dots, underscores, or hyphens
#   @                = Literal @ symbol
#   [a-zA-Z]{2,}     = Two or more letters (bank code like 'ybl', 'paytm', 'okaxis')
UPI_PATTERN = r'[a-zA-Z0-9._-]+@[a-zA-Z]{2,}'

# Bank Account Pattern
# Indian bank accounts are 9-18 digits
# \b means "word boundary" (so we don't match part of larger numbers)
BANK_ACCOUNT_PATTERN = r'\b\d{9,18}\b'

# Indian Phone Number Pattern
# Matches various formats:
#   +91 98765 43210
#   +91-9876543210
#   9876543210
#   91 9876543210
PHONE_PATTERN = r'(?:\+?91[\-\s]?)?[6-9]\d{9}'

# URL/Link Pattern
# Matches: http://... or https://...
# [^\s<>"{}|\\^`\[\]]+ means "any character except whitespace and special chars"
URL_PATTERN = r'https?://[^\s<>"{}|\\^`\[\]]+'

# Email Pattern
# Standard email format: something@something.something
EMAIL_PATTERN = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'


# ============================================================
# SCAM KEYWORDS WITH WEIGHTS
# ============================================================
# Higher weight = stronger scam indicator
# Weight range: 0.0 to 1.0
# If total weight > 0.5, message is likely a scam

SCAM_KEYWORDS = {
    # Lottery/Prize scams (very common in India)
    "lottery": 0.35,
    "winner": 0.30,
    "won": 0.25,
    "prize": 0.30,
    "jackpot": 0.35,
    "lucky draw": 0.35,
    "congratulations": 0.15,  # Lower because it can be genuine

    # Money amounts (Indian currency)
    "lakh": 0.20,
    "lakhs": 0.20,
    "crore": 0.25,
    "crores": 0.25,

    # Financial requests
    "otp": 0.40,           # NEVER share OTP - very strong indicator
    "pin": 0.35,
    "cvv": 0.40,
    "password": 0.35,
    "bank details": 0.35,
    "account number": 0.30,
    "ifsc": 0.25,

    # Urgency tactics
    "urgent": 0.20,
    "immediately": 0.20,
    "expire": 0.15,
    "expiring": 0.15,
    "last chance": 0.25,
    "limited time": 0.20,
    "act now": 0.25,
    "hurry": 0.15,

    # Threat/Fear tactics
    "blocked": 0.25,
    "suspended": 0.25,
    "deactivate": 0.25,
    "legal action": 0.30,
    "police": 0.20,
    "arrest": 0.30,

    # Payment requests
    "processing fee": 0.35,
    "advance payment": 0.40,
    "transfer": 0.15,
    "pay": 0.10,           # Lower because common word
    "deposit": 0.15,
    "gift card": 0.30,

    # Crypto scams
    "bitcoin": 0.20,
    "crypto": 0.15,
    "cryptocurrency": 0.20,
    "investment": 0.15,
    "guaranteed returns": 0.40,
    "double your money": 0.45,

    # Impersonation
    "customer care": 0.20,
    "customer support": 0.20,
    "bank manager": 0.25,
    "rbi": 0.25,           # Reserve Bank of India
    "income tax": 0.20,
    "it department": 0.20,

    # KYC scams (very common)
    "kyc": 0.30,
    "verify": 0.15,
    "verification": 0.15,
    "update": 0.10,        # Lower because common word

    # Refund scams
    "refund": 0.20,
    "cashback": 0.20,
    "reward": 0.15,
    "claim": 0.20,

    # Link sharing
    "click here": 0.25,
    "click link": 0.25,
    "click below": 0.25,
}


# ============================================================
# URGENCY PATTERNS (Regex)
# ============================================================
# These create false sense of urgency to pressure victims

URGENCY_PATTERNS = [
    r'within\s+\d+\s*(hour|minute|day|hr|min)',  # "within 24 hours"
    r'expire[sd]?\s+(today|tomorrow|soon)',       # "expires today"
    r'last\s+chance',                             # "last chance"
    r'final\s+(notice|warning)',                  # "final notice"
    r'immediate(ly)?',                            # "immediately"
    r'urgent(ly)?',                               # "urgently"
    r'asap',                                      # "ASAP"
    r'right\s+now',                               # "right now"
    r'don\'?t\s+(miss|delay|wait)',              # "don't miss"
    r'time\s+(is\s+)?running\s+out',             # "time running out"
    r'act\s+(fast|now|quickly)',                 # "act fast"
    r'before\s+it\'?s?\s+too\s+late',            # "before it's too late"
]


# ============================================================
# SUSPICIOUS KEYWORDS FOR EXTRACTION
# ============================================================
# These are collected and reported in extractedIntelligence

SUSPICIOUS_KEYWORDS = [
    # Scam types
    "lottery", "prize", "winner", "won", "jackpot",
    "lucky draw", "congratulations",

    # Financial
    "transfer", "payment", "pay", "deposit", "withdraw",
    "bank", "account", "upi", "paytm", "phonepe", "gpay",

    # Verification scams
    "verify", "verification", "kyc", "update", "confirm",
    "blocked", "suspended", "locked", "deactivated",

    # Sensitive info requests
    "otp", "pin", "password", "cvv", "card number",

    # Urgency
    "urgent", "immediately", "asap", "hurry", "fast",

    # Crypto
    "gift card", "bitcoin", "crypto", "investment",

    # Support scams
    "customer care", "support", "helpline", "toll free",

    # Refund scams
    "refund", "cashback", "reward", "claim", "bonus",
]


# ============================================================
# HELPER FUNCTION - Calculate scam score from text
# ============================================================

def calculate_keyword_score(text: str) -> tuple[float, list[str]]:
    """
    Calculate scam score based on keywords found in text.

    Args:
        text: The message to analyze

    Returns:
        (score, found_keywords): Score (0.0-1.0) and list of keywords found

    Example:
        >>> calculate_keyword_score("You won lottery! Send OTP now!")
        (0.8, ["won", "lottery", "otp"])
    """
    text_lower = text.lower()
    found_keywords = []
    total_score = 0.0

    for keyword, weight in SCAM_KEYWORDS.items():
        if keyword in text_lower:
            total_score += weight
            found_keywords.append(keyword)

    # Cap the score at 1.0
    return min(total_score, 1.0), found_keywords
