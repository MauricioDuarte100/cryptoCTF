from Crypto.Util.number import long_to_bytes, bytes_to_long
import gmpy2

def is_printable(text):
    """Checks if text contains mostly printable characters."""
    if not text:
        return False
    printable = sum(1 for c in text if 32 <= ord(c) <= 126)
    return printable / len(text) > 0.8

def safe_long_to_bytes(n):
    """Safely converts long to bytes."""
    try:
        return long_to_bytes(n)
    except:
        return None
