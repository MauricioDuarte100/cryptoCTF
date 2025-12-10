"""
Solver for Quadratic CRT Challenge - Lattice Approach

The key insight: x = flag * a where flag is a 512-bit integer.
We have:
  x ≡ y1 (mod m1)  => x - y1 ∈ (m1)
  x ≡ y2 (mod m2)  => x - y2 ∈ (m2)

Since x = c*a for some integer c (the flag), and y1 = d1*a, y2 = d2*a:
  (c - d1)*a ∈ (m1)
  (c - d2)*a ∈ (m2)

This means m1 | (c - d1)*a and m2 | (c - d2)*a in O.

For divisibility in O, we use norms. If m | x in O, then N(m) | N(x) in Z.
N((c-d1)*a) = 7*(c-d1)^2
N(m1) | 7*(c-d1)^2

Actually, let's think differently. In O represented as Z + Z*a:
m1 = m1b + m1a*a
(c - d1)*a = (c - d1)*a

For m1 | (c - d1)*a, we need (c-d1)*a = k * m1 for some k in O.
Let k = kb + ka*a. Then:
(c - d1)*a = (kb + ka*a)(m1b + m1a*a)
           = kb*m1b + (kb*m1a + ka*m1b)*a + ka*m1a*a^2
           = kb*m1b - 7*ka*m1a + (kb*m1a + ka*m1b)*a

Comparing coefficients:
Real: 0 = kb*m1b - 7*ka*m1a
Imag: c - d1 = kb*m1a + ka*m1b

From real: kb*m1b = 7*ka*m1a  =>  kb = 7*ka*m1a/m1b

For kb to be an integer, m1b | 7*ka*m1a.
Let g1 = gcd(m1b, 7*m1a). Then ka must be a multiple of m1b/g1.

Let ka = t * m1b/g1 for some integer t.
Then kb = 7*t*m1a/g1.

Substituting into imaginary equation:
c - d1 = kb*m1a + ka*m1b
       = (7*t*m1a/g1)*m1a + (t*m1b/g1)*m1b
       = t * (7*m1a^2 + m1b^2) / g1
       = t * N(m1) / g1

So: c ≡ d1 (mod N(m1)/g1) where g1 = gcd(m1b, 7*m1a)

Similarly: c ≡ d2 (mod N(m2)/g2) where g2 = gcd(m2b, 7*m2a)

Now we have two congruences in Z, and we can use standard CRT!
"""

from math import gcd

# Given values
d1 = -203371008600523097800583195616627768773035068531216690159577893589770104502640
d2 = -129360120505698427579079931186626281568580626716136890941386025834794673787765

m1a = 293761308418863761154375401834859046163
m1b = 164368523160894975173212618910566251534
m2a = 190179702485369101306013259049822595769
m2b = 299035426520368387707338622172217806294

print("🔍 Quadratic CRT Solver - Lattice/CRT Approach")
print("=" * 50)

# Compute norms
N_m1 = m1b**2 + 7 * m1a**2
N_m2 = m2b**2 + 7 * m2a**2

print(f"\n📊 Values:")
print(f"   d1 = {d1}")
print(f"   d2 = {d2}")
print(f"   N(m1) = {N_m1}")
print(f"   N(m2) = {N_m2}")

# Compute g1, g2
g1 = gcd(m1b, 7 * m1a)
g2 = gcd(m2b, 7 * m2a)

print(f"\n🔗 GCD values:")
print(f"   g1 = gcd(m1b, 7*m1a) = {g1}")
print(f"   g2 = gcd(m2b, 7*m2a) = {g2}")

# Moduli for c
mod1 = N_m1 // g1
mod2 = N_m2 // g2

print(f"\n📊 Moduli for c:")
print(f"   mod1 = N(m1)/g1 = {mod1}")
print(f"   mod2 = N(m2)/g2 = {mod2}")
print(f"   mod1 bits: {mod1.bit_length()}")
print(f"   mod2 bits: {mod2.bit_length()}")

# Reduce d1, d2 modulo their respective moduli
c1 = d1 % mod1
c2 = d2 % mod2

print(f"\n🧮 Reduced residues:")
print(f"   c ≡ {c1} (mod {mod1})")
print(f"   c ≡ {c2} (mod {mod2})")

# Compute gcd of moduli
g_mod = gcd(mod1, mod2)
print(f"\n🔗 gcd(mod1, mod2) = {g_mod}")

# Check CRT compatibility: c1 ≡ c2 (mod gcd)
if c1 % g_mod == c2 % g_mod:
    print("   ✅ CRT compatible!")
else:
    print(f"   ❌ CRT incompatible: {c1 % g_mod} ≠ {c2 % g_mod}")
    # Try other representatives
    print("   Trying to find compatible representatives...")

# Standard CRT when gcd = 1
def chinese_remainder(n1, r1, n2, r2):
    """Compute x such that x ≡ r1 (mod n1) and x ≡ r2 (mod n2)."""
    g = gcd(n1, n2)
    if (r1 - r2) % g != 0:
        return None  # No solution
    
    # Extended Euclidean algorithm
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        g, x, y = extended_gcd(b % a, a)
        return g, y - (b // a) * x, x
    
    _, m1_inv, m2_inv = extended_gcd(n1 // g, n2 // g)
    lcm = n1 * n2 // g
    
    x = (r1 + n1 * ((r2 - r1) // g) * m1_inv) % lcm
    return x

# Apply CRT
c = chinese_remainder(mod1, c1, mod2, c2)

if c is not None:
    print(f"\n✅ CRT solution:")
    print(f"   c = {c}")
    print(f"   c bits: {c.bit_length()}")
    
    # Check if c is in the expected range for a 64-byte flag
    # A 64-byte flag is 512 bits
    if c.bit_length() <= 512:
        print("\n🚩 Attempting to decode flag...")
        try:
            flag_bytes = c.to_bytes(64, 'big')
            print(f"   Flag: {flag_bytes}")
        except Exception as e:
            print(f"   Error: {e}")
            # Maybe c is too small, try padding
            try:
                flag_bytes = c.to_bytes((c.bit_length() + 7) // 8, 'big')
                print(f"   Flag (variable length): {flag_bytes}")
            except Exception as e2:
                print(f"   Error: {e2}")
    else:
        print(f"\n⚠️ c is too large ({c.bit_length()} bits > 512 bits)")
        print("   The combined modulus might not provide enough information.")
        print(f"   Combined modulus bits: {(mod1 * mod2 // gcd(mod1, mod2)).bit_length()}")
        
        # Let's verify the solution anyway
        print("\n🔍 Verifying solution modulo each constraint...")
        if c % mod1 == c1:
            print(f"   ✅ c ≡ d1 (mod mod1)")
        else:
            print(f"   ❌ c ≢ d1 (mod mod1)")
        if c % mod2 == c2:
            print(f"   ✅ c ≡ d2 (mod mod2)")
        else:
            print(f"   ❌ c ≢ d2 (mod mod2)")

else:
    print("\n❌ No CRT solution exists")

# Alternative: the flag might be exactly one of the residue values
# Let's check if d1 or d2 directly give us a valid flag
print("\n📋 Alternative: Check if residues are the flag...")
for name, val in [("d1", abs(d1)), ("d2", abs(d2))]:
    try:
        flag_bytes = val.to_bytes(64, 'big')
        if b'flag' in flag_bytes.lower() or b'ctf' in flag_bytes.lower() or b'FlagY' in flag_bytes:
            print(f"   {name} might be flag: {flag_bytes}")
        else:
            print(f"   {name} decoded but doesn't look like flag")
    except:
        print(f"   {name} is {val.bit_length()} bits, doesn't fit in 64 bytes")
