from typing import TypedDict

SUSPICIOUS_DOMAIN_TOKENS = [
    "secure", "login", "update", "verify", "account", "webscr", 
    "bank", "signin", "confirm", "wallet", "safe", "service", 
    "support", "help", "auth", "apps", "portal"
]

SUSPICIOUS_EXTENSIONS = [
    "xyz", "top", "gq", "ml", "cf", "tk", "ga", 
    "cn", "ru", "work", "click", "loan", "zip", "mov", "link"
]

HIGH_RISK_CCTLDS = [
    ".cn", ".ru", ".tk", ".ml", ".ga", ".cf", ".gq", ".ng", ".ir"
]

TYPO_TARGETS = [
    "g0ogle", "goog1e", "paypa1", "amaz0n", "n3tflix", "fac3book",
    "linked1n", "micr0soft", "apple-id", "icl0ud"
]

class TldDfaResult(TypedDict):
    risk_score: float
    matched_subdomains: list[str]

def dfa_tld(text: str) -> TldDfaResult:
    """
    Scores a URL based on suspicious subdomains, TLDs, or typosquatting.
    """
    text = text.lower().strip()
    matched_subdomains: list[str] = []
    score: float = 0.0

    # Basic extraction
    if "://" in text:
        clean_url = text.split("://", 1)[1]
    else:
        clean_url = text
        
    domain_part = clean_url.split("/")[0]
    domain_part = domain_part.split(":")[0]
    
    labels = domain_part.split(".")
    
    if len(labels) > 1:
        extension = labels[-1]
        if extension in SUSPICIOUS_EXTENSIONS:
            matched_subdomains.append(f".{extension} (Risky TLD)")
            score += 2.0

    for cc in HIGH_RISK_CCTLDS:
        if domain_part.endswith(cc):
            matched_subdomains.append(f"{cc} (High Risk Country)")
            score += 2.0
            break

    for typo in TYPO_TARGETS:
        if typo in domain_part:
            matched_subdomains.append(f"{typo} (Typosquatting)")
            score += 3.0

    for label in labels:
        for token in SUSPICIOUS_DOMAIN_TOKENS:
            if token in label:
                matched_subdomains.append(label)
                score += 1.0
                break 

    return TldDfaResult(
        risk_score=min(score, 10),
        matched_subdomains=matched_subdomains
    )
