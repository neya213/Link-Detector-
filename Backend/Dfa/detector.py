import pprint
from typing import Literal, TypedDict
from .dfa_keywords import dfa_keywords, KeywordDfaResult
from .dfa_symbols import dfa_symbols, SymbolsDfaResult
from .dfa_ip import dfa_ip, IPDfaResult
from .dfa_tld import dfa_domain, DomainDfaResult
from .dfa_encoded import dfa_encoded, EncodedDfaResult

class SuspiciousFlags(TypedDict):
    has_suspicious_keywords: bool
    has_symbol_abuse: bool
    has_ip_address: bool
    has_suspicious_tld: bool
    has_encoded_chars: bool

class DfaPayload(TypedDict):
    keywords: KeywordDfaResult
    symbols: SymbolsDfaResult
    ip: IPDfaResult
    domain: DomainDfaResult
    encoded: EncodedDfaResult

# TODO: refine unified_phishing_detector to pass the DfaResults in the frontend as well.

def unified_phishing_detector(url: str) -> tuple[float, SuspiciousFlags, Literal["SAFE", "SUSPICIOUS", "HIGH RISK / PHISHING"], DfaPayload]:
    """
    Analyzes a URL for phishing indicators using DFA-based detection methods.
    Returns: total_score, flags dict, verdict string
    """

    # this all calculates the scoring of each dfa
    keywords: KeywordDfaResult = dfa_keywords(url)
    symbols: SymbolsDfaResult = dfa_symbols(url)
    ip: IPDfaResult = dfa_ip(url)
    domain: DomainDfaResult = dfa_domain(url)
    encoded: EncodedDfaResult = dfa_encoded(url)

    encoded_risk_score = len(encoded["high_risk"]) + min(len(encoded["low_risk"]), 5) / 1.2

    total_score = (
        keywords["risk_score"] +
        symbols["risk_score"] +
        ip["risk_score"] +
        domain["risk_score"] +
        encoded_risk_score
    )

    # makes a verdict if the risk_score is too suspicious, this can be tuned.
    flags: SuspiciousFlags = {
        "has_suspicious_keywords": bool(keywords["risk_score"] > 0),
        "has_symbol_abuse": bool(symbols["risk_score"] > 0),
        "has_ip_address": bool(ip["risk_score"] > 0),
        "has_suspicious_tld": bool(domain["risk_score"] > 0),
        "has_encoded_chars": encoded["is_risky"]
    }

    if total_score == 0:
        verdict: Literal["SAFE", "SUSPICIOUS", "HIGH RISK / PHISHING"] = "SAFE"
    elif total_score <= 5:
        verdict = "SUSPICIOUS"
    else:
        verdict = "HIGH RISK / PHISHING"

    payload = DfaPayload(
        ip=ip,
        domain=domain,
        symbols=symbols,
        encoded=encoded,
        keywords=keywords,
    )

    return total_score, flags, verdict, payload
