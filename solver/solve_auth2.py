"""
Solver for CryptoHack Authentication-2 Challenge

This solver implements polynomial root finding in GF(2^128) using
the Berlekamp algorithm with optimizations for small degree polynomials.

Alternative: Uses a trick - since we have a degree-4 polynomial,
we can try randomized factorization which is efficient enough for
small degrees.
"""

import requests
import re
from json import dumps
import random
from typing import List, Tuple, Optional

HOST = "archive.cryptohack.org"
PORT = 59670
BASE_URL = f"http://{HOST}:{PORT}"


def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def unescape_cookie(cookie_val):
    if not cookie_val:
        return ""
    if cookie_val.startswith('"') and cookie_val.endswith('"'):
        cookie_val = cookie_val[1:-1]
    def replace_octal(match):
        return chr(int(match.group(1), 8))
    return re.sub(r'\\([0-7]{3})', replace_octal, cookie_val)


def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, 'big')


def int_to_bytes(n: int, length: int = 16) -> bytes:
    return n.to_bytes(length, 'big')


# ============ Challenge's exact GHASH implementation ============

def bytes_to_bits(X: bytes):
    res = []
    for b in X:
        for bb in bin(b)[2:].zfill(8):
            res.append(int(bb))
    return res


def bits_to_bytes(X):
    X = [str(x) for x in X]
    res = []
    for b in range(0, len(X), 8):
        res.append(int("".join(X[b:b+8]), 2))
    return bytes(res)


def gcm_mul_challenge(X: bytes, Y: bytes) -> bytes:
    """EXACT copy of the challenge's mul() function."""
    BLOCK_LEN = 16
    R = bytes_to_bits(b"\xe1" + b"\x00"*(BLOCK_LEN-1))
    X_bits = bytes_to_bits(X)
    V = bytes_to_bits(Y)
    Z = [0x00 for _ in range(BLOCK_LEN*8)]
    
    for i in range(BLOCK_LEN*8):
        if X_bits[i] != 0:
            Z = [z^v for z,v in zip(Z,V)]
        if V[-1] != 0:
            V = [0] + V[:-1]
            V = [v^r for v,r in zip(V, R)]
        else:
            V = [0] + V[:-1]
    
    return bits_to_bytes(Z)


def ghash_challenge(data: bytes, H: bytes) -> bytes:
    """EXACT copy of challenge's GHASH."""
    Y = b"\x00" * 16
    for i in range(0, len(data), 16):
        block = data[i:i+16]
        Y = gcm_mul_challenge(xor(Y, block), H)
    return Y


def build_ghash_buffer(C: bytes) -> bytes:
    u = 16 * ((len(C) + 15) // 16) - len(C)
    buf = C + b"\x00" * u
    buf += (0).to_bytes(8, "big")
    buf += (len(C) * 8).to_bytes(8, "big")
    return buf


# ============ GF(2^128) Integer Arithmetic ============
# Match challenge's representation: MSB-first bits

def gf_mul_int(a: int, b: int) -> int:
    """Multiply two 128-bit integers in GF(2^128) matching challenge representation."""
    # Convert to bytes, multiply, convert back
    a_bytes = int_to_bytes(a, 16)
    b_bytes = int_to_bytes(b, 16)
    result_bytes = gcm_mul_challenge(a_bytes, b_bytes)
    return bytes_to_int(result_bytes)


def gf_pow(base: int, exp: int) -> int:
    """Compute base^exp in GF(2^128)."""
    result = 1
    while exp > 0:
        if exp & 1:
            result = gf_mul_int(result, base)
        base = gf_mul_int(base, base)
        exp >>= 1
    return result


def gf_inv(a: int) -> int:
    """Compute multiplicative inverse using Fermat's little theorem."""
    if a == 0:
        raise ValueError("Cannot invert 0")
    return gf_pow(a, (1 << 128) - 2)


# ============ Polynomial over GF(2^128) ============

def poly_trim(p: List[int]) -> List[int]:
    """Remove leading zeros."""
    while len(p) > 1 and p[-1] == 0:
        p = p[:-1]
    return list(p)


def poly_add(p: List[int], q: List[int]) -> List[int]:
    """Add two polynomials (XOR)."""
    max_len = max(len(p), len(q))
    result = [0] * max_len
    for i in range(len(p)):
        result[i] ^= p[i]
    for i in range(len(q)):
        result[i] ^= q[i]
    return poly_trim(result)


def poly_mul(p: List[int], q: List[int]) -> List[int]:
    """Multiply two polynomials."""
    if not p or not q:
        return [0]
    result = [0] * (len(p) + len(q) - 1)
    for i, a in enumerate(p):
        if a == 0:
            continue
        for j, b in enumerate(q):
            if b == 0:
                continue
            result[i + j] ^= gf_mul_int(a, b)
    return poly_trim(result)


def poly_divmod(p: List[int], q: List[int]) -> Tuple[List[int], List[int]]:
    """Compute (p // q, p % q)."""
    p = poly_trim(list(p))
    q = poly_trim(list(q))
    
    if len(q) == 1 and q[0] == 0:
        raise ValueError("Division by zero")
    
    if len(p) < len(q):
        return [0], p
    
    quotient = [0] * (len(p) - len(q) + 1)
    q_lead_inv = gf_inv(q[-1])
    
    while len(p) >= len(q) and any(p):
        p = poly_trim(p)
        if len(p) < len(q):
            break
        
        degree_diff = len(p) - len(q)
        coeff = gf_mul_int(p[-1], q_lead_inv)
        quotient[degree_diff] = coeff
        
        for i in range(len(q)):
            p[i + degree_diff] ^= gf_mul_int(coeff, q[i])
        
        p = poly_trim(p)
    
    return poly_trim(quotient), poly_trim(p)


def poly_gcd(p: List[int], q: List[int]) -> List[int]:
    """Compute GCD of two polynomials."""
    while True:
        q = poly_trim(q)
        if len(q) == 1 and q[0] == 0:
            break
        _, r = poly_divmod(p, q)
        p, q = q, r
    # Make monic
    if p[-1] != 0 and p[-1] != 1:
        inv = gf_inv(p[-1])
        p = [gf_mul_int(c, inv) for c in p]
    return poly_trim(p)


def poly_eval(p: List[int], x: int) -> int:
    """Evaluate polynomial at x using Horner's method."""
    result = 0
    for coeff in reversed(p):
        result = gf_mul_int(result, x) ^ coeff
    return result


def poly_mod(p: List[int], m: List[int]) -> List[int]:
    """Compute p mod m."""
    _, r = poly_divmod(p, m)
    return r


def poly_pow_mod(base: List[int], exp: int, mod: List[int]) -> List[int]:
    """Compute base^exp mod mod using repeated squaring."""
    result = [1]
    base = poly_mod(base, mod)
    
    count = 0
    while exp > 0:
        count += 1
        if count % 10 == 0:
            print(f"      Squaring iteration {count}...")
        
        if exp & 1:
            result = poly_mod(poly_mul(result, base), mod)
        base = poly_mod(poly_mul(base, base), mod)
        exp >>= 1
    
    return result


def find_polynomial_roots(poly: List[int], max_iterations: int = 100) -> List[int]:
    """
    Find roots of polynomial in GF(2^128) using Cantor-Zassenhaus.
    """
    poly = poly_trim(poly)
    degree = len(poly) - 1
    
    if degree == 0:
        return []
    
    if degree == 1:
        # ax + b = 0  =>  x = b/a = b * a^(-1)
        a, b = poly[1], poly[0]
        if a == 0:
            return []
        return [gf_mul_int(b, gf_inv(a))]
    
    print(f"[*] Finding roots of degree-{degree} polynomial...")
    
    # Step 1: Compute gcd(poly, x^(2^128) - x)
    # x^(2^128) mod poly using 128 squarings
    print("    Computing x^(2^128) mod poly (128 squarings)...")
    
    x_pow = poly_pow_mod([0, 1], 1 << 128, poly)
    
    # x^(2^128) - x = x^(2^128) + x in GF(2)
    x_pow_minus_x = poly_add(x_pow, [0, 1])
    
    print("    Computing GCD...")
    g = poly_gcd(poly, x_pow_minus_x)
    g = poly_trim(g)
    
    print(f"    GCD degree: {len(g) - 1}")
    
    if len(g) <= 1:
        return []
    
    if len(g) == 2:
        # Single root
        a, b = g[1], g[0]
        return [gf_mul_int(b, gf_inv(a))]
    
    # Recursive factoring using random splitting
    roots = []
    factors = [g]
    
    for iteration in range(max_iterations):
        if not factors:
            break
        
        f = factors.pop()
        f = poly_trim(f)
        
        if len(f) <= 1:
            continue
        
        if len(f) == 2:
            a, b = f[1], f[0]
            roots.append(gf_mul_int(b, gf_inv(a)))
            continue
        
        # Try random trace-based splitting
        delta = random.getrandbits(128)
        
        # Compute Tr(x + delta) mod f
        # Tr(y) = y + y^2 + y^4 + ... + y^(2^127)
        term = poly_mod([delta, 1], f)  # x + delta
        trace = [0]
        
        for i in range(128):
            trace = poly_add(trace, term)
            term = poly_mod(poly_mul(term, term), f)
        
        # gcd(f, trace) or gcd(f, trace + 1)
        g1 = poly_gcd(f, trace)
        g2 = poly_gcd(f, poly_add(trace, [1]))
        
        if len(g1) > 1 and len(g1) < len(f):
            factors.append(g1)
            _, remainder = poly_divmod(f, g1)
            if len(remainder) <= 1:
                # f / g1 is the other factor
                quotient, _ = poly_divmod(f, g1)
                factors.append(quotient)
        elif len(g2) > 1 and len(g2) < len(f):
            factors.append(g2)
            quotient, _ = poly_divmod(f, g2)
            factors.append(quotient)
        else:
            # No split found, put back and try again
            factors.insert(0, f)
    
    return roots


def solve():
    print(f"[*] Target: {BASE_URL}")
    
    session = requests.Session()
    
    print("\n[*] Step 1: Reset database")
    session.get(f"{BASE_URL}/reset-db")
    
    target = dumps({"username": "A", "role": "super_admin"})
    for ulen in range(1, 50):
        username = "A" * ulen
        original = dumps({"username": username, "role": "guest"})
        if len(original) == len(target):
            break
    
    print(f"[*] Step 2: Register user '{username}'")
    session.post(f"{BASE_URL}/register", data={"username": username, "password": "test"})
    
    print("[*] Step 3: Login")
    resp = session.post(f"{BASE_URL}/login", data={"username": username, "password": "test"},
                        allow_redirects=False)
    
    token = unescape_cookie(resp.cookies.get('auth', ''))
    if not token or ';' not in token:
        print(f"[-] Failed to get token")
        return
    
    ct_hex, tag_hex = token.split(";")
    C1 = bytes.fromhex(ct_hex)
    T1 = bytes.fromhex(tag_hex)
    P1 = original.encode()
    P2 = target.encode()
    
    print(f"[+] Got token")
    
    # Recover keystream
    K = xor(C1, P1)
    S1 = xor(T1, K[:16])
    C2 = xor(K, P2)
    
    buf1 = build_ghash_buffer(C1)
    buf2 = build_ghash_buffer(C2)
    
    print(f"\n[*] Step 4: Recovered K and S1")
    print(f"    K:  {K.hex()}")
    print(f"    S1: {S1.hex()}")
    
    # Build polynomial: B0*H^4 + B1*H^3 + B2*H^2 + B3*H + S1 = 0
    # Coefficients: [S1, B3, B2, B1, B0]
    blocks = [bytes_to_int(buf1[i:i+16]) for i in range(0, len(buf1), 16)]
    S1_int = bytes_to_int(S1)
    
    poly = [S1_int]  # H^0
    for i in reversed(range(len(blocks))):
        poly.append(blocks[i])
    
    print(f"\n[*] Step 5: Find H (polynomial root finding)")
    roots = find_polynomial_roots(poly)
    
    print(f"[+] Found {len(roots)} root(s)")
    
    for root in roots:
        H = root
        H_bytes = int_to_bytes(H, 16)
        print(f"\n[*] Step 6: Testing H = {H:032x}")
        
        # Verify
        S_computed = ghash_challenge(buf1, H_bytes)
        if S_computed != S1:
            print(f"[-] Verification failed")
            continue
        
        print(f"[+] H verified!")
        
        # Forge tag
        S2 = ghash_challenge(buf2, H_bytes)
        T2 = xor(S2, K[:16])
        
        forged_token = f"{C2.hex()};{T2.hex()}"
        print(f"[+] Forged token: {forged_token}")
        
        session.cookies.clear()
        session.cookies.set('auth', forged_token, domain=HOST)
        resp = session.get(f"{BASE_URL}/admin")
        
        print(f"\n[*] Step 7: Response:")
        print("=" * 60)
        print(resp.text)
        print("=" * 60)
        
        if 'flag' in resp.text.lower():
            flags = re.findall(r'[A-Za-z0-9_]+\{[^}]+\}', resp.text)
            if flags:
                print(f"\n[+] FLAG: {flags[0]}")
            return
    
    print("\n[-] No valid H found")


if __name__ == "__main__":
    print("=" * 60)
    print("Authentication-2 Solver")
    print("=" * 60)
    
    try:
        solve()
    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()
