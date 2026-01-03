ENCODED_PATTERNS = ["%20", "%3A", "%2F", "%40", "%3F", "&amp;", "&#", "&#x","%2520", "%253A","%252F","&amp;","&lt;","&gt;","&quot;","&apos;","&#","&#x"]

def dfa_encoded(text):
    text_lower = text.lower()
    
    for pattern in ENCODED_PATTERNS:
        if pattern in text_lower:
            return True
    
    return False

