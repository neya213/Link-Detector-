
from typing import TypedDict

class SymbolsDfaResult(TypedDict):
    risk_score: float
    symbols: dict[str, int]

SUSPICIOUS_SYMBOLS = [
    "..", "--", ".-.", "<", ">", "@", "~", "+", "%"
]

def dfa_symbols(text: str) -> SymbolsDfaResult:
    text = text.lower().strip()
    score = 0.0
    matched_symbols: dict[str, int] = dict()

    for symbol in SUSPICIOUS_SYMBOLS:
        count = text.count(symbol)
        if count:
            matched_symbols[symbol] = count;
            score += min(count * 1.0, 5.0)

    # extract domain
    if "://" in text:
        domain = text.split("://", 1)[1].split("/", 1)[0]
    else:
        domain = text.split("/", 1)[0]

    # remove port if present
    domain = domain.split(":", 1)[0]

    # normalize for long URLs
    if len(text) > 50:
        score /= (len(text) / 50) ** 0.3

    return SymbolsDfaResult(
        risk_score=round(score, 2),
        symbols=matched_symbols
    )
