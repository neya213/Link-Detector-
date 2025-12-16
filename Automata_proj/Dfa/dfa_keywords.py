SUSPICIOUS_KEYWORDS = [
    "verify",
    "verification",
    "secure",
    "security",
    "login",
    "log-in",
    "signin",
    "sign-in",
    "reset",
    "recover",
    "recovery",
    "update",
    "confirm",
    "authentication",
    "authorize",
    "urgent",
    "immediately",
    "alert",
    "warning",
    "suspended",
    "blocked",
    "limited",
    "disabled",
    "locked",
    "expired",
    "payment",
    "billing",
    "invoice",
    "refund",
    "transaction",
    "bank",
    "wallet",
    "crypto",
    "bitcoin",
    "paypal",
    "account",
    "support",
    "service",
    "customer",
    "helpdesk",
    "admin",
    "administrator",
    "free",
    "bonus",
    "reward",
    "winner",
    "claim",
    "prize",
    "gift",
    "offer",
    "webscr",
    "validate",
    "session",
    "token",
    "redirect",
]


def dfa_keywords(text):

    text_lower = text.lower()
    
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in text_lower:
            return True  
    

