
from typing import TypedDict

# Example suspicious tokens (you can expand this)
SUSPICIOUS_DOMAIN_TOKENS = [
    "secure", "login", "update", "verify", "account", "webscr", "bank"
]

class DomainDfaResult(TypedDict):
    risk_score: float
    matched_subdomains: list[str]

def dfa_domain(text: str) -> DomainDfaResult:
    """
    Scores a URL based on suspicious subdomains or tokens.
    Each matching subdomain or token is worth 1 point.
    """
    text = text.lower().strip()
    matched_subdomains: list[str] = []
    score: float = 0.0

    # domain extraction!
    if "://" in text:
        domain = text.split("://", 1)[1].split("/")[0]
    else:
        domain = text.split("/")[0]

    domain = domain.split(":")[0]  # remove port if present
    labels = domain.split(".")

    candidates = labels[:-1]

    for label in candidates:
        for token in SUSPICIOUS_DOMAIN_TOKENS:
            if token in label:
                matched_subdomains.append(label)
                score += 1.0  # each match is 1 point
                break  # avoid double-counting the same label

    return DomainDfaResult(
        risk_score=score,
        matched_subdomains=matched_subdomains
    )
