import pprint
from typing import Literal, TypedDict

from .dfa_visualization import build_dfa_visualizations, DfaVisualizations
from .dfa_keywords import dfa_keywords, KeywordDfaResult
from .dfa_symbols import dfa_symbols, SymbolsDfaResult
from .dfa_ip import dfa_ip, IPDfaResult
from .dfa_tld import dfa_tld, TldDfaResult
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
    domain: TldDfaResult
    encoded: EncodedDfaResult


def unified_phishing_detector(url: str) -> tuple[float, SuspiciousFlags, Literal["SAFE", "SUSPICIOUS", "HIGH RISK / PHISHING"], DfaPayload, DfaVisualizations]:
    """
    Analyzes a URL for phishing indicators using DFA-based detection methods.
    Returns: total_score, flags dict, verdict string
    """

    # this all calculates the scoring of each dfa
    keywords: KeywordDfaResult = dfa_keywords(url)
    symbols: SymbolsDfaResult = dfa_symbols(url)
    ip: IPDfaResult = dfa_ip(url)
    tld: TldDfaResult = dfa_tld(url)
    encoded: EncodedDfaResult = dfa_encoded(url)

    encoded_risk_score = min(len(encoded["high_risk"]) + min(len(encoded["low_risk"]), 5) / 1.2, 5)

    total_score = (
        keywords["risk_score"] +
        symbols["risk_score"] +
        ip["risk_score"] +
        tld["risk_score"] +
        encoded_risk_score
    )

    # makes a verdict if the risk_score is too suspicious, this can be tuned.
    flags: SuspiciousFlags = {
        "has_suspicious_keywords": bool(keywords["risk_score"] > 0),
        "has_symbol_abuse": bool(symbols["risk_score"] > 0),
        "has_ip_address": bool(ip["risk_score"] > 0),
        "has_suspicious_tld": bool(tld["risk_score"] > 0),
        "has_encoded_chars": encoded["is_risky"]
    }

    if 0 <= total_score <= 5:
        verdict: Literal["SAFE", "SUSPICIOUS", "HIGH RISK / PHISHING"] = "SAFE"
    elif 6 <= total_score <= 12:
        verdict = "SUSPICIOUS"
    else:
        verdict = "HIGH RISK / PHISHING"

    payload = DfaPayload(
        ip=ip,
        domain=tld,
        symbols=symbols,
        encoded=encoded,
        keywords=keywords,
    )
    visualizations = build_dfa_visualizations(keywords, symbols, ip, tld, encoded)

    return total_score, flags, verdict, payload, visualizations
