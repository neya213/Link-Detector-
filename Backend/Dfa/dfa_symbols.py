from typing import TypedDict

class SymbolsDfaResult(TypedDict):
    risk_score: float
    symbols: dict[str, int]

SUSPICIOUS_SYMBOLS = [
    "..", "--", ".-.",       # Structural breaking
    "<", ">",                # HTML injection indicators
    "@",                     # Obfuscation (user:pass@domain.com)
    "~",                     # Old unix home directory indicators
    "+",                     # Often used in email aliases
    "%",                     # Encoding indicator
    "=",                     # Parameter passing in weird places
    "xn--",                  # Punycode indicator (fake foreign letters)
    "0",                     # Zero often replaces 'O' in homograph attacks
    "|",                     # Pipe character
    "$",                     # Variable indicator
]

def dfa_symbols(text: str) -> SymbolsDfaResult:
    text = text.lower().strip()
    score = 0.0
    matched_symbols: dict[str, int] = dict()

    for symbol in SUSPICIOUS_SYMBOLS:
        count = text.count(symbol)
        if count:
            matched_symbols[symbol] = count
            # Punycode is higher risk
            if symbol == "xn--":
                score += 3.0
            else:
                score += min(count * 1.0, 5.0)

    # Normalize for long URLs
    if len(text) > 50:
        score /= (len(text) / 50) ** 0.3

    return SymbolsDfaResult(
        risk_score=round(score, 2),
        symbols=matched_symbols
    )