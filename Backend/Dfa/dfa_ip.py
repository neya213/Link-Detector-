def is_valid_ip(ip_str):
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


def dfa_ip(text):
    text = text.strip()

    if "://" in text:
        host = text.split("://", 1)[1].split("/", 1)[0]
    else:
        host = text.split("/", 1)[0]

    host = host.split(":", 1)[0]

    return is_valid_ip(host)
