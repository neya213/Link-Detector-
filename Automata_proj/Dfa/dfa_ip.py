def is_valid_ip(ip_str):

    parts = ip_str.split('.')
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit():
            return False
        num = int(part)
        if num < 0 or num > 255:
            return False
    return True

def dfa_ip(text):

    text_lower = text.lower()
    
    if '://' in text_lower:
        host_portion = text_lower.split('://')[1].split('/')[0]
    else:
        host_portion = text_lower.split('/')[0]
    
    host = host_portion.split(':')[0]
    
    if is_valid_ip(host):
        return True
    return False


