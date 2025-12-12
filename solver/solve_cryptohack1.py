import socket
import json
import struct
import binascii
import time
import random

BLOCK_LEN = 16

# --- GF(2^128) Arithmetic ---

def bytes_to_long(b):
    return int.from_bytes(b, 'big')

def long_to_bytes(l):
    return l.to_bytes(BLOCK_LEN, 'big')

def xor_bytes(a, b):
    # a and b can be different lengths, xor prefix
    return bytes(x^y for x,y in zip(a,b))

class GF128:
    def __init__(self, val):
        if isinstance(val, bytes):
            self.val = bytes_to_long(val)
        elif isinstance(val, int):
            self.val = val
        elif isinstance(val, GF128):
            self.val = val.val
        else:
            raise ValueError(f"Invalid type {type(val)}")
            
    def __add__(self, other):
        if isinstance(other, int): other = GF128(other)
        return GF128(self.val ^ other.val)
    
    def __sub__(self, other):
        return self + other
        
    def __mul__(self, other):
        if isinstance(other, int): other = GF128(other)
        x = self.val
        y = other.val
        res = 0
        v = y
        for i in range(128):
            if (x >> (127 - i)) & 1:
                res ^= v
            if v & 1:
                v = (v >> 1) ^ (0xE1 << 120)
            else:
                v >>= 1
        return GF128(res)
    
    def inv(self):
        base = self
        exp = (1 << 128) - 2
        res = GF128(1 << 127) 
        
        while exp > 0:
            if exp % 2 == 1:
                res = res * base
            base = base * base
            exp //= 2
        return res
        
    def __eq__(self, other):
        if isinstance(other, int): other = GF128(other)
        return self.val == other.val
        
    def __hash__(self):
        return hash(self.val)

    def __pow__(self, exponent):
        res = IDENTITY
        base = self
        while exponent > 0:
            if exponent % 2:
                res = res * base
            base = base * base
            exponent //= 2
        return res

    def __repr__(self):
        return hex(self.val)

IDENTITY = GF128(1 << 127)
ZERO = GF128(0)

# --- Polynomials ---

class Poly:
    def __init__(self, coeffs):
        self.coeffs = [GF128(c) for c in coeffs]
        self.trim()

    def trim(self):
        while len(self.coeffs) > 1 and self.coeffs[0] == ZERO:
            self.coeffs.pop(0)

    def degree(self):
        return len(self.coeffs) - 1

    def __add__(self, other):
        d1 = len(self.coeffs)
        d2 = len(other.coeffs)
        n = max(d1, d2)
        a = [ZERO]*(n-d1) + self.coeffs
        b = [ZERO]*(n-d2) + other.coeffs
        return Poly([x+y for x,y in zip(a,b)])
        
    def __mul__(self, other):
        new_deg = self.degree() + other.degree()
        res = [ZERO] * (new_deg + 1)
        
        for i, c1 in enumerate(self.coeffs):
            deg1 = self.degree() - i
            for j, c2 in enumerate(other.coeffs):
                deg2 = other.degree() - j
                target_deg = deg1 + deg2
                # target index (from start 0 .. new_deg) = new_deg - target_deg
                idx = new_deg - target_deg
                res[idx] = res[idx] + (c1 * c2)
        return Poly(res)

    def mod(self, other):
        return self.divmod(other)[1]

    def divmod(self, other):
        if other.degree() < 0 or (other.degree() == 0 and other.coeffs[0] == ZERO):
            raise ZeroDivisionError
            
        rem = Poly(self.coeffs)
        divisor = other
        
        # Quotient deg = deg(self) - deg(other)
        if rem.degree() < divisor.degree():
            return (Poly([ZERO]), rem)
            
        q_deg = rem.degree() - divisor.degree()
        # Initialize quotient coeffs with ZEROs
        # Size q_deg + 1
        quotient_coeffs = [ZERO] * (q_deg + 1)
        
        while rem.degree() >= divisor.degree() and not (rem.degree()==0 and rem.coeffs[0]==ZERO):
            deg_diff = rem.degree() - divisor.degree()
            lead_rem = rem.coeffs[0]
            lead_div = divisor.coeffs[0]
            
            factor = lead_rem * lead_div.inv()
            
            # Add factor to quotient at position corresponding to x^deg_diff
            # Array index for x^k is (q_deg - k)
            quotient_coeffs[q_deg - deg_diff] = quotient_coeffs[q_deg - deg_diff] + factor
            
            sub_coeffs = [c * factor for c in divisor.coeffs] + [ZERO]*deg_diff
            sub_poly = Poly(sub_coeffs)
            rem = rem + sub_poly
            rem.trim()
            
        return (Poly(quotient_coeffs), rem)

def gcd_poly(p1, p2):
    while not (p2.degree() == 0 and p2.coeffs[0] == ZERO):
        p1, p2 = p2, p1.mod(p2)
    return p1

def find_roots(P):
    # Returns a list of roots (GF128 elements)
    if P.degree() == 1:
        # ax + b = 0 -> x = b/a
        return [P.coeffs[1] * P.coeffs[0].inv()]
    
    if P.degree() == 0:
        return []
        
    # Randomized Trace Method
    # Pick random delta
    # Trace(delta * x) = sum (delta*x)^(2^i)
    # G = GCD(P, Trace)
    # If degree splits, recurse.
    
    attempts = 0
    while attempts < 5: 
        print(f"[DEBUG] Root Finding Attempt {attempts+1}/5")
        delta = GF128(random.getrandbits(128))
        
        # Calculate TracePoly mod P
        x_poly = Poly([delta, ZERO]) # Degree 1: delta*x + 0
        
        T = Poly([ZERO])
        curr = x_poly
        
        # Iterative calculation
        for i in range(128):
            T = T + curr
            curr = (curr * curr).mod(P)
            
        g = gcd_poly(P, T)
        
        deg = g.degree()
        if 0 < deg < P.degree():
            # Split!
            r1 = find_roots(g)
            r2 = find_roots(P.divmod(g)[1]) 
            # divmod returns quotient. wait. P = g * q + 0.
            # roots of P are union roots of g and q.
            # divmod returns (q, r). r should be 0.
            q, r = P.divmod(g)
            r2 = find_roots(q)
            return list(set(r1 + r2))
            
        attempts += 1
        
    return []

# --- Attack Logic ---

def connect():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(('archive.cryptohack.org', 61277))
    return s

def reset_and_get_token(username):
    # RESET DB
    s = connect()
    s.send(b"GET /reset-db HTTP/1.1\r\nHost: archive.cryptohack.org\r\nConnection: close\r\n\r\n")
    # consume
    while True:
        try:
            if not s.recv(4096): break
        except: break
    s.close()
    
    # REGISTER
    s = connect()
    payload = f"username={username}&password=pass"
    req = f"POST /register HTTP/1.1\r\nHost: archive.cryptohack.org\r\nContent-Length: {len(payload)}\r\nContent-Type: application/x-www-form-urlencoded\r\nConnection: close\r\n\r\n{payload}"
    s.send(req.encode())
    while True:
        try:
            if not s.recv(4096): break
        except: break
    s.close()
            
    # LOGIN
    s = connect()
    payload = f"username={username}&password=pass"
    req = f"POST /login HTTP/1.1\r\nHost: archive.cryptohack.org\r\nContent-Length: {len(payload)}\r\nContent-Type: application/x-www-form-urlencoded\r\nConnection: close\r\n\r\n{payload}"
    s.send(req.encode())
    
    cookie = None
    curr = b""
    while True:
        try:
            chunk = s.recv(4096)
            if not chunk: break
            curr += chunk
        except: break
    s.close()
    
    lines = curr.decode(errors='ignore').split('\r\n')
    for l in lines:
        if "Set-Cookie" in l and "auth=" in l:
            try:
                cms = l.split("auth=")[1]
                cookie = cms.split(";")[0]
            except: pass
            
    if not cookie:
        print("[-] Failed to get cookie")
    return cookie

def get_ghash_coeffs(C):
    if len(C) % 16 != 0:
        C_pad = C + b'\x00' * (16 - len(C) % 16)
    else:
        C_pad = C
    len_block = (0).to_bytes(8, 'big') + (len(C)*8).to_bytes(8, 'big')
    fulling = C_pad + len_block
    blocks = [fulling[i:i+16] for i in range(0, len(fulling), 16)]
    return blocks

def solve():
    print("[*] Starting attack with Root Finding...")
    
    # Long username to cover target length
    # Target: {"username": "admin", "role": "super_admin"} -> 45 bytes.
    # need 3 blocks.
    user_padding = "A" * 48 
    token = reset_and_get_token(user_padding)
    if not token:
        return
        
    print(f"[DEBUG] Retrieved Token: {token}")
    
    # Sanitize
    token = token.strip('"')
    if r'\073' in token:
        token = token.replace(r'\073', ';')
    
    if ';' not in token:
        # Check if URL encoded? %3B
        import urllib.parse
        token = urllib.parse.unquote(token)
        print(f"[DEBUG] Decoded Token: {token}")
        
    C1, T1_hex = token.split(';')
    C1 = bytes.fromhex(C1)
    T1 = bytes.fromhex(T1_hex)
    
    # 1. Recover Keystream - Try multiple formats
    candidates = []
    
    # Format 1: Std, Username first
    p1 = {"username": user_padding, "role": "guest"}
    candidates.append(json.dumps(p1).encode())
    
    # Format 2: Compact, Username first
    candidates.append(json.dumps(p1, separators=(',', ':')).encode())
    
    # Format 3: Std, Role first
    # Manually construct string to ensure order
    # json.dumps keeps order in modern python, but let's be safe
    s_std = '{' + f'"role": "guest", "username": "{user_padding}"' + '}'
    candidates.append(s_std.encode())
    
    s_cpt = '{' + f'"role":"guest","username":"{user_padding}"' + '}'
    candidates.append(s_cpt.encode())
    
    # Format 4: Spaces in keys? Unlikely.
    # Format 5: default dumps with spaces
    # In python 3.12, order is preserved.
    
    print(f"[+] Testing {len(candidates)} JSON formats...")
    
    found_flag = False
    
    for idx, P1_guess in enumerate(candidates):
        if len(P1_guess) != len(C1):
            continue
            
        print(f"[*] Trying P1 Candidate {idx}...")
        keystream = xor_bytes(C1, P1_guess)
        
        # Forge
        target_dict = {"username": "admin", "role": "super_admin"}
        # Try both compact and std for target?
        # Does not matter for server parsing, as long as it is valid JSON.
        # But we need K to cover it.
        # Target length must be <= Keystream length
        
        P_new = json.dumps(target_dict, separators=(',', ':')).encode()
        
        if len(keystream) < len(P_new):
            # Try shorter target or pad username more?
            # user_padding was "A"*48.
            # Plaintext len approx 48 + 30 = 78.
            # Target len approx 45.
            # Sufficient.
            pass
            
        C_new = xor_bytes(P_new, keystream[:len(P_new)])
        
        # Fake Tag (Since ignored)
        T_new_hex = T1.hex() # Reuse T1
        
        token_new = C_new.hex() + ';' + T_new_hex
        
        # Verify
        # Add quotes to cookie?
        s = connect()
        req = f"GET /admin HTTP/1.1\r\nHost: archive.cryptohack.org\r\nCookie: auth=\"{token_new}\"\r\nConnection: close\r\n\r\n"
        s.send(req.encode())
        resp = b""
        while True:
            try:
                chunk = s.recv(4096)
                if not chunk: break
                resp += chunk
            except: break
            
        resp_decoded = resp.decode(errors='ignore')
        if "BZHCTF" in resp_decoded:
             print(f"\n[SUCCESS] Flag found with candidate {idx}!")
             print(resp_decoded)
             found_flag = True
             break
        else:
             print(f"[-] Candidate {idx} failed.")
             # print(resp_decoded) # Noisy

    if not found_flag:
        print("[-] All candidates failed. Maybe padding issue?")

if __name__ == "__main__":
    solve()
