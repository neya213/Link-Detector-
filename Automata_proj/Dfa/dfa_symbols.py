def dfa_symbols(text):
    text = text.lower().strip()

    if ".." in text or "--" in text or ".-." in text:
        return True

    if "://" in text:
        domain = text.split("://", 1)[1].split("/", 1)[0]
    else:
        domain = text.split("/", 1)[0]

    domain = domain.split(":", 1)[0]

    if domain.count(".") > 3:
        return True

    labels = domain.split(".")
    for label in labels:
        if label.count("-") > 2:
            return True

    return False
