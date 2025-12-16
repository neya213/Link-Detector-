SUSPICIOUS_TLDS = [
    ".xyz",
    ".top",
    ".click",
    ".link",
    ".live",
    ".online",
    ".site",
    ".info",
    ".zip",
    ".tk",
    ".ml",
    ".ga",
    ".cf",
    ".gq",
    ".icu",
    ".support",
    ".review",
    ".country",
    ".stream",
    ".loan",
    ".money",
    ".account",
    ".bank",
    ".app",
    ".cloud",
    ".service",
]


def dfa_tld(text):
    text_lower = text.lower()
    
    if '://' in text_lower:
        domain = text_lower.split('://')[1].split('/')[0]
    else:
        domain = text_lower.split('/')[0]
    domain = domain.split(':')[0]
    
    if '.' in domain:
        tld = domain.split('.')[-1]
        if tld in SUSPICIOUS_TLDS:
            return True
    
    return False

