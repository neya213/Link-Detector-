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

def is_valid_ipv6(ip_str: str) -> bool:
    if ip_str.count(":") < 2:
        return False
    
    valid_chars = set("0123456789abcdef:")
    return all(c in valid_chars for c in ip_str.lower())

class IPDfaResult(TypedDict):
    ip: str | None
    risk_score: float

def dfa_ip(text: str) -> IPDfaResult:
    text = text.strip()

    if "://" in text:
        host = text.split("://", 1)[1].split("/", 1)[0]
    else:
        host = text.split("/", 1)[0]

    if "[" in host and "]" in host:
        host_check = host.split("]")[0].replace("[", "")
        if is_valid_ipv6(host_check):
            return IPDfaResult(ip=host_check, risk_score=5)
    else:
        host_check = host.split(":", 1)[0]
        if is_valid_ip(host_check):
            return IPDfaResult(ip=host_check, risk_score=5)

    return IPDfaResult(
        ip=None,
        risk_score=0
    )