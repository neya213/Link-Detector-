import re
from typing import TypedDict


# Assign weights (tunable) to keywords
SUSPICIOUS_KEYWORDS_WEIGHTS = {
    "verify": 3,
    "verification": 3,
    "secure": 2,
    "security": 2,
    "login": 2,
    "log-in": 2,
    "signin": 2,
    "sign-in": 2,
    "reset": 2,
    "recover": 2,
    "recovery": 2,
    "update": 1,
    "confirm": 2,
    "authentication": 3,
    "authorize": 3,
    "urgent": 2,
    "immediately": 2,
    "alert": 2,
    "warning": 2,
    "suspended": 2,
    "blocked": 2,
    "limited": 1,
    "disabled": 2,
    "locked": 2,
    "expired": 1,
    "payment": 2,
    "billing": 2,
    "invoice": 2,
    "refund": 2,
    "transaction": 2,
    "bank": 2,
    "wallet": 2,
    "crypto": 2,
    "bitcoin": 2,
    "paypal": 2,
    "account": 2,
    "support": 1,
    "service": 1,
    "customer": 1,
    "helpdesk": 2,
    "admin": 3,
    "administrator": 3,
    "free": 1,
    "bonus": 1,
    "reward": 1,
    "winner": 2,
    "claim": 2,
    "prize": 2,
    "gift": 1,
    "offer": 1,
    "webscr": 3,
    "validate": 2,
    "session": 1,
    "token": 2,
    "redirect": 1,
}

class KeywordDfaResult(TypedDict):
    risk_score: float
    keywords: dict[str, int]

def dfa_keywords(text: str) -> KeywordDfaResult:
    text_lower = text.lower()
    keywords: dict[str, int] = dict()
    risk_score: float = 0.0
    
    for keyword, weight in SUSPICIOUS_KEYWORDS_WEIGHTS.items():
        matches = re.findall(rf"\b{re.escape(keyword)}\b", text_lower)
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
