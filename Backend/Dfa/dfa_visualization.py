from typing import TypedDict

from .dfa_keywords import KeywordDfaResult
from .dfa_symbols import SymbolsDfaResult
from .dfa_ip import IPDfaResult
from .dfa_tld import DomainDfaResult
from .dfa_encoded import EncodedDfaResult

class DfaVisualization(TypedDict):
    detected: bool
    method: str
    states_visited: list[str]

class DfaVisualizations(TypedDict):
    keywords: DfaVisualization
    symbols: DfaVisualization
    ip_address: DfaVisualization
    tld: DfaVisualization
    encoding: DfaVisualization


def build_dfa_visualizations(
    keywords: KeywordDfaResult,
    symbols: SymbolsDfaResult,
    ip: IPDfaResult,
    domain: DomainDfaResult,
    encoded: EncodedDfaResult
) -> DfaVisualizations:

    # --- 1. KEYWORD LOGIC ---
    # Differentiate between a simple match and a high-risk flood of keywords
    kw_states = ["q0"]
    if keywords["risk_score"] > 0:
        kw_states.append("q_match") # Found a keyword
        
        # If score is very high (multiple urgencies), add a critical state
        if keywords["risk_score"] > 4:
             kw_states.append("q_critical")

    # --- 2. SYMBOL LOGIC ---
    # Show the "loop" effect. If score is high, it means we looped many times.
    sym_states = ["q0"]
    if symbols["risk_score"] > 0:
        sym_states.append("q_detect") # Symbol found
        if symbols["risk_score"] >= 3:
            sym_states.append("q_accumulate") # Score accumulation loop active

    # --- 3. IP ADDRESS LOGIC ---
    # Distinguish IPv4 (4 states) from IPv6 (Colon detection)
    ip_states = ["q0"]
    if ip["risk_score"] > 0:
        if ":" in str(ip["ip"]): 
            # IPv6 Logic
            ip_states = ["q0", "q_hex", "q_colon", "q_ipv6"]
        else:
            # IPv4 Logic (Standard 4 octets)
            ip_states = ["q0", "q1", "q2", "q3"]

    # --- 4. TLD & DOMAIN LOGIC ---
    # Check *why* it failed (Typosquatting vs Bad Extension)
    tld_states = ["q0"]
    if domain["risk_score"] > 0:
        # Check the tags we added in dfa_tld.py
        reasons = str(domain["matched_subdomains"])
        
        if "Typosquatting" in reasons:
            tld_states = ["q0", "q_scan", "q_typo_match"]
        elif "Country" in reasons:
             tld_states = ["q0", "q_geo_check", "q_bad_cc"]
        else:
             tld_states = ["q0", "q_ext_check", "q_bad_tld"]

    # --- 5. ENCODING LOGIC ---
    # Distinguish High Risk (Null bytes) from Low Risk (Spaces)
    enc_states = ["q0"]
    if encoded["is_risky"]:
        enc_states.append("q_percent") # Saw a %
        
        if len(encoded["high_risk"]) > 0:
            enc_states.append("q_critical_hex") # Null byte or XSS
        else:
            enc_states.append("q_encoded") # Just excessive encoding

    return DfaVisualizations(
        keywords={
            "detected": keywords["risk_score"] > 0,
            "method": "Pattern matching with keyword DFA",
            "states_visited": kw_states
        },
        symbols={
            "detected": symbols["risk_score"] > 0,
            "method": "Symbol frequency analysis DFA",
            "states_visited": sym_states
        },
        ip_address={
            "detected": ip["risk_score"] > 0,
            "method": "IP address pattern DFA",
            "states_visited": ip_states
        },
        tld={
            "detected": domain["risk_score"] > 0,
            "method": "TLD & Typosquatting verification",
            "states_visited": tld_states
        },
        encoding={
            "detected": encoded["is_risky"],
            "method": "URL encoding detection DFA",
            "states_visited": enc_states
        },
    )