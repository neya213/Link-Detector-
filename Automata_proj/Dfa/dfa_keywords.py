SUSPICIOUS_KEYWORDS = ["verify", "secure", "login", "reset", "confirm", "account", "update,invoice, payment, bill, order, transfer, shipping, document, file, 0, http://"]

def dfa_keywords(text):

    text_lower = text.lower()
    
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in text_lower:
            return True  
    

