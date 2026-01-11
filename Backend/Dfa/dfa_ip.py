

from typing import TypedDict


def is_valid_ip(ip_str: str):
    parts = ip_str.split(".")
    if len(parts) != 4:
        return False

    for part in parts:
        if not part.isdigit():
            return False

        if len(part) > 1 and part.startswith("0"):
            return False

        num = int(part)
        if num < 0 or num > 255:
            return False

    return True

class IPDfaResult(TypedDict):
    ip: str | None
    risk_score: float

def dfa_ip(text: str) -> IPDfaResult:
    text = text.strip()

    if "://" in text:
        host = text.split("://", 1)[1].split("/", 1)[0]
    else:
        host = text.split("/", 1)[0]

    host = host.split(":", 1)[0]

    return IPDfaResult(
        ip=host if is_valid_ip(host) else None,
        risk_score=5 if is_valid_ip(host) else 0
    )
