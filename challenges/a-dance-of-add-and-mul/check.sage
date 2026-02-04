
p = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab
K = GF(p)
E = EllipticCurve(K, (0, 4))
n = E.order()
print(f"Order: {n}")
print(f"Factorized order: {n.factor()}")
gens = E.gens()
print(f"Generators: {len(gens)}")
for i, g in enumerate(gens):
    print(f"G{i+1} order: {g.order()}")
