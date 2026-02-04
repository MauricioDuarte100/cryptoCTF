
import hashlib
from Crypto.Util.number import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import sympy

def decrypt_flag(ct, params):
    key = hashlib.sha256(str(params).encode()).digest()
    cipher = AES.new(key, AES.MODE_CBC, iv=ct[:16])
    return unpad(cipher.decrypt(ct[16:]), 16)

def solve():
    s1 = 4052328936969804578
    s2 = 8676271689691567645
    s3 = 2647032430467963079
    s4 = 6612596210231769351
    enc_flag_hex = "0c5355c5bb76b2a86aa7cf53279fb2350883865f2ca7423ff47512278a59a8db1ed85e82e0d84c2fec52e29d0b3aefd97d791f11edf18efdf1febc07ae860b8b"
    enc_flag = bytes.fromhex(enc_flag_hex)

    D1 = s2 - s1
    D2 = s3 - s2
    D3 = s4 - s3

    T = abs(D1 * D3 - D2 * D2)
    print(f"T = {T}")
    
    # Factorize T
    factors = sympy.factorint(T)
    print(f"Factors: {factors}")
    
    p = None
    for f in factors:
        if f.bit_length() == 64 and sympy.isprime(f):
            p = f
            break
    
    if p is None:
        print("Could not find p")
        return

    print(f"Found p: {p}")
    
    # a = (s3 - s2) / (s2 - s1) mod p
    # a = D2 * pow(D1, -1, p) % p
    a = (D2 * pow(D1, -1, p)) % p
    # b = s2 - a*s1 mod p
    b = (s2 - a * s1) % p
    # s0 = (s1 - b) / a mod p
    s0 = ((s1 - b) * pow(a, -1, p)) % p

    params = (p, a, b, s0)
    print(f"Params: {params}")
    try:
        flag = decrypt_flag(enc_flag, params)
        print(f"FLAG: {flag.decode()}")
    except Exception as e:
        print(f"Error decrypting: {e}")

if __name__ == "__main__":
    solve()
