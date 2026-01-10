
SUSPICIOUS_SYMBOLS = [
    "..", "--", ".-.", "<", ">", "@", "~", "+", "%", "?", "&"
]

def suspicious_symbols_checker(text: str) -> bool:
    """
    Checks a URL for suspicious symbols and patterns.
    Returns True if any suspicious patterns are found.
    """
    text = text.lower().strip()

    for symbol in SUSPICIOUS_SYMBOLS:
        if symbol in text:
            return True

    # extract domain
    if "://" in text:
        domain = text.split("://", 1)[1].split("/", 1)[0]
    else:
        domain = text.split("/", 1)[0]

    # remove port if present
    domain = domain.split(":", 1)[0]

    # check for too many subdomains
    if domain.count(".") > 4:
        return True

    labels = domain.split(".")
    for label in labels:
        if label.count("-") > 2:
            return True

    return False
