from typing import TypedDict

HIGH_RISK_ENCODED = [ 
    "%00",                      # null byte (Critical)
    "%2e%2e",                   # .. directory traversal
    "%252e", "%252f",           # double encoded
    "%40",                      # @ symbol
    "%0a", "%0d",               # Newline injection (CRLFs)
    "%3c", "%3e",               # < and > (XSS attempts)
    "javascript:",              # Protocol handler
    "data:",                    # Data URI
    "vbscript:",                # VBScript
    "&#x", "&#",                # numeric HTML entities
    "0x", "\\u",                # Hex/Unicode obfuscation
]

LOW_RISK_ENCODED = [
    "%20", "%3a", "%2f",        # common URL encodings (space, :, /)
    "&amp;", "&lt;", "&gt;",
    "&quot;", "&apos;",
    "%26", "%3f",               # & ?
]

class EncodedDfaResult(TypedDict):
    is_risky: bool
    low_risk: list[str]
    high_risk: list[str]

def dfa_encoded(text: str) -> EncodedDfaResult:
    text = text.lower()
    low_risk: list[str] = []
    high_risk: list[str] = []

    for pattern in HIGH_RISK_ENCODED:
        if pattern in text:
            high_risk.append(pattern)

    for pattern in LOW_RISK_ENCODED:
        if pattern in text:
            low_risk.append(pattern)

    res = EncodedDfaResult(
        is_risky=len(low_risk) >= 5 or len(high_risk) >= 1,
        low_risk=low_risk,
        high_risk=high_risk
    )
    return res