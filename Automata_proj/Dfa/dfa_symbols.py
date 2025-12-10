def dfa_symbols(text):
    text_lower = text.lower()

    if '..' in text_lower or '--' in text_lower:
        return True
    
    if '.-.' in text_lower:
        return True
    
    if '://' in text_lower:
        domain = text_lower.split('://')[1].split('/')[0]
    else:
        domain = text_lower.split('/')[0]
    
    dot_count = domain.count('.')
    if dot_count > 3:
        return True
    
    return False 
