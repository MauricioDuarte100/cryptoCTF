
p = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
K = GF(p)
E = EllipticCurve(K, (0, 4))
G = E.abelian_group()
inv = G.invariants()
d1 = inv[0]
print(f"d1: {d1}")
print(f"d1 factorized: {d1.factor()}")
