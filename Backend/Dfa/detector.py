from typing import Literal, TypedDict
from .dfa_keywords import dfa_keywords
from .dfa_symbols import dfa_symbols
from .dfa_ip import dfa_ip
from .dfa_tld import dfa_tld
from .dfa_encoded import dfa_encoded


class SuspiciousFlags(TypedDict):
    has_suspicious_keywords: bool
    has_symbol_abuse: bool
    has_ip_address: bool
    has_suspicious_tld: bool
    has_encoded_chars: bool

def unified_phishing_detector(url: str) -> tuple[int, SuspiciousFlags, Literal["SAFE", "SUSPICIOUS", "HIGH RISK / PHISHING"]]:
    """
    Analyzes a URL for phishing indicators using DFA-based detection methods.
    """
    results: SuspiciousFlags = SuspiciousFlags(
        has_suspicious_keywords=dfa_keywords(url),
        has_symbol_abuse=dfa_symbols(url),
        has_ip_address=dfa_ip(url),
        has_suspicious_tld=dfa_tld(url),
        has_encoded_chars=dfa_encoded(url)
    )

    match_count = sum(1 for v in results.values() if v)

    if match_count == 0:
        risk = "SAFE"
    elif match_count <= 2:
        risk = "SUSPICIOUS"
    else:
        risk = "HIGH RISK / PHISHING"

    return match_count, results, risk
