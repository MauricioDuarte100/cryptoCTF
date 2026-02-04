
p = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
K = GF(p)
E = EllipticCurve(K, (0, 4))
dv = E.elementary_divisors()
print(f"Invariants: {dv}")
n = E.order()
print(f"n factorized: {n.factor()}")
for q, e in n.factor():
    if e >= 2:
        print(f"Prime factor {q}^{e} might be in d1")
