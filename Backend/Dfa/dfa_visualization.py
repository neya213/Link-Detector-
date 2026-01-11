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

    return DfaVisualizations(
        keywords={
            "detected": keywords["risk_score"] > 0,
            "method": "Pattern matching with keyword DFA",
            "states_visited": ["q0", "q1"] if keywords["risk_score"] > 0 else ["q0"]
        },
        symbols={
            "detected": symbols["risk_score"] > 0,
            "method": "Symbol frequency analysis DFA",
            "states_visited": ["q0", "q1", "q2"] if symbols["risk_score"] > 0 else ["q0"]
        },
        ip_address={
            "detected": ip["risk_score"] > 0,
            "method": "IP address pattern DFA",
            "states_visited": ["q0", "q1", "q2", "q3"] if ip["risk_score"] > 0 else ["q0"]
        },
        tld={
            "detected": domain["risk_score"] > 0,
            "method": "TLD verification DFA",
            "states_visited": ["q0", "q_tld"] if domain["risk_score"] > 0 else ["q0"]
        },
        encoding={
            "detected": encoded["is_risky"],
            "method": "URL encoding detection DFA",
            "states_visited": ["q0", "q_percent", "q_encoded"] if encoded["is_risky"] else ["q0"]
        },
    )
