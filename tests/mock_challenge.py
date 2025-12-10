from Crypto.Util.number import getPrime, bytes_to_long

flag = b"flag{test_rsa_solve_success}"
p = getPrime(512)
q = getPrime(512)
n = p * q
e = 3
m = bytes_to_long(flag)
c = pow(m, e, n)

print(f"n = {n}")
print(f"e = {e}")
print(f"c = {c}")
