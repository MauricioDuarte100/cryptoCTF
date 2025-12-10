# Simple ECC Challenge
# Curve: y^2 = x^3 + ax + b (mod p)
# Small field for BSGS

p = 10007
a = 1
b = 1
# y^2 = x^3 + x + 1 (mod 10007)

# Generator G
G = (0, 1) # 1 = 0 + 0 + 1. Correct.

# Secret n
n = 1234
# P = n * G

# Simple point multiplication for setup
def add(P, Q, p, a):
    if P is None: return Q
    if Q is None: return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and y1 != y2: return None
    if x1 == x2:
        m = (3*x1*x1 + a) * pow(2*y1, -1, p)
    else:
        m = (y2 - y1) * pow(x2 - x1, -1, p)
    m = m % p
    x3 = (m*m - x1 - x2) % p
    y3 = (m*(x1 - x3) - y1) % p
    return (x3, y3)

def mul(n, P, p, a):
    R = None
    for i in range(n.bit_length()):
        if (n >> i) & 1:
            R = add(R, P, p, a)
        P = add(P, P, p, a)
    return R

P = mul(n, G, p, a)

print(f"p = {p}")
print(f"a = {a}")
print(f"b = {b}")
print(f"G = {G}")
print(f"P = {P}")
print("Find n such that P = n * G")
