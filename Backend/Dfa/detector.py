from dfa_keywords import dfa_keywords
from dfa_symbols import dfa_symbols
from dfa_ip import dfa_ip
from dfa_tld import dfa_tld
from dfa_encoded import dfa_encoded


def unified_phishing_detector(url):
    """
    Analyzes a URL for phishing indicators using DFA-based detection methods.
    
    Returns:
        tuple: (match_count, results_dict, risk_level)
    """
    results = {
        "Suspicious Keywords": dfa_keywords(url),
        "Symbol Abuse": dfa_symbols(url),
        "IP-Based URL": dfa_ip(url),
        "Suspicious TLD": dfa_tld(url),
        "Encoded Characters": dfa_encoded(url)
    }

    match_count = sum(results.values())

    if match_count == 0:
        risk = "SAFE"
    elif match_count <= 2:
        risk = "SUSPICIOUS"
    else:
        risk = "HIGH RISK / PHISHING"

    return match_count, results, risk
