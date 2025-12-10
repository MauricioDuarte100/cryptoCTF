from Crypto.Util.number import getPrime, inverse, bytes_to_long

def create_wiener_vulnerable_keys(bits=1024):
    while True:
        p = getPrime(bits // 2)
        q = getPrime(bits // 2)
        n = p * q
        phi = (p - 1) * (q - 1)
        # d should be small, e.g., < 1/3 n^(1/4)
        d = getPrime(bits // 8) 
        try:
            e = inverse(d, phi)
            return n, e, d
        except:
            continue

n, e, d = create_wiener_vulnerable_keys()
flag = b"flag{wiener_attack_success}"
m = bytes_to_long(flag)
c = pow(m, e, n)

print(f"n = {n}")
print(f"e = {e}")
print(f"c = {c}")
