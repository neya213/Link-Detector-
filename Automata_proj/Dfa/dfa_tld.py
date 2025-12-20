SUSPICIOUS_TLDS = [
    "xyz", "top", "click", "link", "live", "online", "site",
    "info", "zip", "tk", "ml", "ga", "cf", "gq", "icu",
    "support", "review", "country", "stream", "loan",
    "money", "account", "bank", "app", "cloud", "service"
]


def dfa_tld(text):
    text = text.lower().strip()

    if "://" in text:
        domain = text.split("://", 1)[1].split("/")[0]
    else:
        domain = text.split("/")[0]

    domain = domain.split(":")[0]

    if "." not in domain:
        return False

    tld = domain.split(".")[-1]
    return tld in SUSPICIOUS_TLDS
