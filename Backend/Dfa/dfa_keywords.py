import re
from typing import TypedDict

# Assign weights (tunable) to keywords
SUSPICIOUS_KEYWORDS_WEIGHTS = {
    # --- Urgency & Action (High Weight) ---
    "verify": 3, "verification": 3, "suspend": 3, "suspended": 3,
    "restrict": 3, "restricted": 3, "block": 3, "blocked": 3,
    "expire": 2, "expired": 2, "attempt": 2, "unusual": 2,
    "login": 2, "signin": 2, "log-in": 2, "sign-in": 2,
    "confirm": 2, "confirmation": 2, "action": 1, "required": 2,
    "immediate": 2, "immediately": 2, "urgent": 2,
    "unlock": 3, "reactivate": 3, "restore": 2,

    # --- Financial & Banking (Very High Weight) ---
    "bank": 2, "banking": 2, "wallet": 3, "payment": 2,
    "transaction": 2, "invoice": 2, "billing": 2, "receipt": 2,
    "paypal": 3, "coinbase": 3, "binance": 3, "metamask": 3,
    "trustwallet": 3, "ledger": 3, "trezor": 3, "crypto": 2,
    "bitcoin": 2, "ethereum": 2, "refund": 3, "deposit": 2,
    "withdraw": 2, "withdrawal": 2, "tax": 2, "irs": 3,

    # --- Logistics & Shipping (High Weight - Very Common) ---
    "delivery": 2, "shipping": 2, "parcel": 2, "package": 2,
    "tracking": 2, "shipment": 2, "courier": 2, "address": 1,
    "postal": 2, "customs": 2, "fee": 2, "pending": 2,

    # --- Enterprise & HR (Targeting Students/Employees) ---
    "payroll": 3, "hr": 2, "human-resources": 2, "salary": 2,
    "benefits": 2, "employee": 1, "staff": 1, "portal": 1,
    "intranet": 2, "vpn": 2, "citrix": 2, "okta": 3, "sso": 3,
    "docusign": 3, "document": 1, "shared": 1, "file": 1,

    # --- Security & Tech Spoofing ---
    "secure": 1, "security": 1, "protect": 1, "protection": 1,
    "auth": 2, "authentication": 2, "authenticator": 2,
    "update": 1, "upgrade": 1, "support": 1, "service": 1,
    "account": 1, "client": 1, "user": 1, "admin": 3,
    "password": 3, "credential": 3, "recovery": 2,

    # --- Threat/Fear Tactics ---
    "violation": 3, "banned": 3, "legal": 2, "warrant": 3,
    "police": 2, "court": 2, "lawsuit": 2, "fine": 2,
    "cancel": 2, "termination": 3, "deactivation": 3,
    
    # --- Technical Evasion Terms ---
    "webscr": 4, "cmd": 3, "dispatch": 3, "login-dispatch": 3,
    "scr": 2, "secure-code": 3, "token": 2, "session": 2,
    "redirect": 1, "validate": 2, "bonus": 1, "gift": 1, "prize": 2,
}

class KeywordDfaResult(TypedDict):
    risk_score: float
    keywords: dict[str, int]

def dfa_keywords(text: str) -> KeywordDfaResult:
    text_lower = text.lower()
    keywords: dict[str, int] = dict()
    risk_score: float = 0.0
    
    for keyword, weight in SUSPICIOUS_KEYWORDS_WEIGHTS.items():
       
        if keyword in text_lower:
            matches = re.findall(re.escape(keyword), text_lower)
            count = len(matches)
            if count > 0:
                keywords[keyword] = count
                risk_score += weight * count

    if len(text_lower) > 50:
        risk_score /= (len(text_lower) / 50) ** 0.3 # dampening the effect of long URLs

    return KeywordDfaResult(
        risk_score=round(risk_score, 2),
        keywords=keywords
    )
