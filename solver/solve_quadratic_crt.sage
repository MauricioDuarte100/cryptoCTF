"""
Solver for Quadratic CRT Challenge

The challenge computes:
- x = flag * a  (where a = sqrt(-7))
- y1 = x mod m1
- y2 = x mod m2

We use CRT over the ring of integers of Q(sqrt(-7)) to recover x.
"""

# This is SageMath code - run with `sage solve_quadratic_crt.sage`

# Define the quadratic field
K.<a> = QuadraticField(-7)
O = K.maximal_order()

# Given values from output.txt
y1 = -203371008600523097800583195616627768773035068531216690159577893589770104502640*a
y2 = -129360120505698427579079931186626281568580626716136890941386025834794673787765*a
m1 = 293761308418863761154375401834859046163*a + 164368523160894975173212618910566251534
m2 = 190179702485369101306013259049822595769*a + 299035426520368387707338622172217806294

print("🔍 Analyzing the challenge...")
print(f"   m1 = {m1}")
print(f"   m2 = {m2}")

# Compute ideals
I1 = O.ideal(m1)
I2 = O.ideal(m2)

print(f"\n📊 Ideal norms:")
print(f"   N(I1) = {I1.norm()}")
print(f"   N(I2) = {I2.norm()}")

# Check if they are coprime
I_gcd = I1 + I2
print(f"\n🔗 gcd(I1, I2) = {I_gcd}")
print(f"   Is unit ideal? {I_gcd == O.ideal(1)}")

# CRT: Find x such that x ≡ y1 (mod m1) and x ≡ y2 (mod m2)
# In a Dedekind domain, we can use the CRT for ideals

# Method: Solve x = y1 + m1*k for some k in O
# Such that x ≡ y2 (mod m2)
# => y1 + m1*k ≡ y2 (mod m2)
# => m1*k ≡ (y2 - y1) (mod m2)

# Since x = flag * a (purely imaginary), we know x has no real part
# x = c * a for some integer c

# y1 = x mod m1 means x = y1 + m1*k1 for some k1 in O
# y2 = x mod m2 means x = y2 + m2*k2 for some k2 in O

# Since x = c*a, and y1 = d1*a (purely imaginary), we have:
# c*a = d1*a + m1*k1
# => m1*k1 = (c - d1)*a

# Let's work in the quotient ring O/I1*I2
# Using CRT: O/(I1*I2) ≅ O/I1 × O/I2 when I1 + I2 = O

# SageMath approach: use the crt function if available, or manual

print("\n🧮 Applying CRT...")

# We need to find x such that:
# x ≡ y1 (mod m1)
# x ≡ y2 (mod m2)

# First, find elements u, v such that u*m1 + v*m2 = 1 (Bezout)
# Then x = y1*v*m2 + y2*u*m1

# In O, we can compute extended GCD using ideals
# d = gcd(m1, m2) should be a unit

# Try direct computation
# d, u, v = xgcd(m1, m2) in O

# SageMath doesn't have direct xgcd for O elements, but we can use:
# The fact that O is a UFD (unique factorization domain) for Q(sqrt(-7))
# Actually Q(sqrt(-7)) has class number 1, so O is a PID

# Method: Convert to ideal arithmetic
# If I1 + I2 = O, then there exist alpha in I1, beta in I2 such that alpha + beta = 1

# Let's compute the extended gcd
# In SageMath, we can lift from the quotient

# Alternative: The modular reduction gives us y values
# x = y1 + t1*m1 for some t1
# x = y2 + t2*m2 for some t2

# Since x = c*a for integer c (flag), and y1, y2 are given, we solve:
# c*a - y1 ≡ 0 (mod m1)
# c*a - y2 ≡ 0 (mod m2)

# Note y1 = d1*a and y2 = d2*a for some integers d1, d2

d1 = -203371008600523097800583195616627768773035068531216690159577893589770104502640
d2 = -129360120505698427579079931186626281568580626716136890941386025834794673787765

# So we need (c - d1)*a ≡ 0 (mod m1)
# and (c - d2)*a ≡ 0 (mod m2)

# This means a | (c - d1)*a in O/m1*O ? No wait...
# x mod m1 means: x - y1 is divisible by m1 in O
# So m1 | (c*a - d1*a) = (c - d1)*a

# For m1 | (c-d1)*a, we need (c-d1)*a in the ideal (m1)
# Since a is not divisible by m1 in general, we need m1 | (c - d1) in some sense

# Actually in O, the divisibility is more complex because O is not Z

# Let me use a different approach: lattice-based
# x = c*a, c is unknown integer (the flag)
# We have congruences in O

# The norm of m1*m2 gives us the product in Z
# N(m1) * N(m2) gives us modulus in Z for the norm of x

# Actually, let's try the following:
# x = y1 + k*m1 for some k in O
# x - y1 = k*m1
# We want x = c*a, so c*a - y1 = c*a - d1*a = (c - d1)*a = k*m1

# So k = (c - d1)*a / m1
# For k to be in O, we need m1 | (c - d1)*a

# Let m1 = m1_a * a + m1_b (given values)
# N(m1) = m1_b^2 + 7*m1_a^2 (norm in Q(sqrt(-7)))

# For m1 | (c - d1)*a, we look at norms:
# N(m1) | N((c - d1)*a) = 7*(c - d1)^2

# Similar for m2

# This gives us:
# N(m1) | 7*(c - d1)^2
# N(m2) | 7*(c - d2)^2

# Since N(m1), N(m2) are large, and c is at most 512 bits...
# Actually wait, the modular equation is directly in O

# Let me just try SageMath's CRT functionality

try:
    # Try using SageMath's built-in CRT for number fields
    x_recovered = crt([y1, y2], [m1, m2])
    print(f"\n✅ CRT result: x = {x_recovered}")
except Exception as e:
    print(f"\n⚠️ Built-in CRT failed: {e}")
    print("   Trying manual approach...")
    
    # Manual CRT using lattice
    # x = y1 (mod m1) => x - y1 divisible by m1
    # x = y2 (mod m2) => x - y2 divisible by m2
    
    # Since x = c*a for integer c, and y1 = d1*a, y2 = d2*a:
    # (c - d1)*a divisible by m1
    # (c - d2)*a divisible by m2
    
    # In ideal terms: a*(c - d1) in ideal(m1)
    # For the principal ideal (c - d1)*a*O to be in (m1), 
    # we need to find c such that this holds
    
    # The key insight: since O is a PID for Q(sqrt(-7)),
    # we have (m1) = (g1) for some generator g1
    # And we need g1 | (c - d1)*a
    
    # Let's compute using the ideal directly
    # c ≡ d1 (mod N(m1)/gcd(N(a), N(m1))) roughly
    
    # Simpler: work over Z for the imaginary coefficient
    # x = c*a, y1 = d1*a, m1 = m1a*a + m1b
    # x mod m1 in terms of imaginary parts...
    
    # Actually, let's extract the constraint on c:
    # (c - d1)*a = k*(m1a*a + m1b) for some k = ka*a + kb in O
    # => (c - d1)*a = ka*a*(m1a*a + m1b) + kb*(m1a*a + m1b)
    # => (c - d1)*a = ka*m1a*a^2 + ka*m1b*a + kb*m1a*a + kb*m1b
    # =>            = ka*m1a*(-7) + (ka*m1b + kb*m1a)*a + kb*m1b
    # => -7*ka*m1a + kb*m1b = 0  (real part)
    # => ka*m1b + kb*m1a = c - d1 (imaginary coefficient)
    
    # From real part: kb = 7*ka*m1a / m1b
    # Sub into imaginary: ka*m1b + (7*ka*m1a / m1b)*m1a = c - d1
    #                    ka*(m1b + 7*m1a^2/m1b) = c - d1
    #                    ka*(m1b^2 + 7*m1a^2)/m1b = c - d1
    #                    ka*N(m1)/m1b = c - d1
    
    # So c - d1 = ka * N(m1) / m1b  => must be an integer
    # => c ≡ d1 (mod N(m1) / gcd(N(m1), m1b))
    
    m1a = 293761308418863761154375401834859046163
    m1b = 164368523160894975173212618910566251534
    m2a = 190179702485369101306013259049822595769
    m2b = 299035426520368387707338622172217806294
    
    from math import gcd
    
    N_m1 = m1b^2 + 7*m1a^2
    N_m2 = m2b^2 + 7*m2a^2
    
    print(f"\n📊 Norms:")
    print(f"   N(m1) = {N_m1}")
    print(f"   N(m2) = {N_m2}")
    
    # The constraint is: c ≡ d1 (mod something derived from m1)
    # And: c ≡ d2 (mod something derived from m2)
    
    # From the analysis: divisibility requires c - d1 to be divisible by N(m1)/gcd(N(m1), m1b)
    # But this is getting complex. Let me use a lattice approach.
    
    # Lattice: Find c such that (c - d1)*a ∈ (m1) and (c - d2)*a ∈ (m2)
    
    # Since both y1 and y2 are pure imaginary (coefficient of 'a' only),
    # and x = c*a is also pure imaginary, the constraints simplify.
    
    # Let's use the norm constraint directly:
    # N(x) = 7*c^2
    # x mod m1 = y1 => x = y1 + k1*m1 for some k1 in O
    # Taking norms: N(x) = N(y1 + k1*m1)
    
    # This is getting complex. Let me just try computing in SageMath quotient rings.
    
    # Work in O/m1*O
    R1 = O.quotient(I1, 'b')
    R2 = O.quotient(I2, 'c')
    
    # The CRT isomorphism: O/(I1*I2) ≅ O/I1 × O/I2
    # We want x in O such that x mod I1 = y1 and x mod I2 = y2
    
    # Use Bezout: find alpha in O such that alpha*m1 ≡ 1 (mod m2)
    # Then x = y1 + (y2 - y1)*alpha*m1
    
    # To find alpha, we solve alpha*m1 + beta*m2 = 1
    # This is xgcd in O
    
    # Since O is a PID, we can use the Euclidean algorithm
    # Let's compute gcd(m1, m2) iteratively
    
    def euclidean_gcd_O(a_val, b_val):
        """Euclidean algorithm in the ring O."""
        while b_val != 0:
            # q = a_val // b_val in O (need to find appropriate quotient)
            # This is tricky; use norm-based division
            n = b_val.norm()
            q = (a_val * b_val.conjugate()) / n
            # Round q to nearest element of O
            q_real = round(q[0])
            q_imag = round(q[1])
            q_O = O(q_imag * a + q_real)
            r = a_val - q_O * b_val
            a_val, b_val = b_val, r
        return a_val
    
    g = euclidean_gcd_O(m1, m2)
    print(f"\n🔗 gcd(m1, m2) = {g}")
    print(f"   gcd norm = {g.norm()}")
    
    # If gcd is a unit (norm 1), we can do CRT
    if g.norm() == 1:
        print("   ✅ m1 and m2 are coprime!")
        
        # Extended Euclidean algorithm to find u, v such that u*m1 + v*m2 = 1
        def extended_gcd_O(a_val, b_val):
            """Extended Euclidean algorithm in O."""
            old_r, r = a_val, b_val
            old_s, s = O(1), O(0)
            old_t, t = O(0), O(1)
            
            while r != 0:
                n = r.norm()
                q_approx = (old_r * r.conjugate()) / n
                q_real = round(q_approx[0])
                q_imag = round(q_approx[1])
                q = O(q_imag * a + q_real)
                
                old_r, r = r, old_r - q * r
                old_s, s = s, old_s - q * s
                old_t, t = t, old_t - q * t
            
            return old_r, old_s, old_t
        
        g, u, v = extended_gcd_O(m1, m2)
        print(f"   u*m1 + v*m2 = {u*m1 + v*m2}")
        
        # CRT: x = y1*v*m2 + y2*u*m1
        x_recovered = y1 * v * m2 + y2 * u * m1
        
        # Reduce modulo m1*m2
        modulus = m1 * m2
        
        print(f"\n✅ Recovered x = {x_recovered}")
        
        # Verify
        check1 = (x_recovered - y1) % m1
        check2 = (x_recovered - y2) % m2
        print(f"\n🔍 Verification:")
        print(f"   (x - y1) mod m1 = 0? {check1 == 0}")
        print(f"   (x - y2) mod m2 = 0? {check2 == 0}")

# If we have x = c*a, extract c
if 'x_recovered' in dir() and x_recovered is not None:
    # x = c*a means x[0] = 0 and x[1] = c
    # In SageMath, x_recovered might be in O, so extract coefficients
    try:
        coeffs = list(x_recovered)  # [real_part, imag_coefficient]
        c = coeffs[1]  # Coefficient of a
        print(f"\n🚩 Flag bytes:")
        print(f"   c = {c}")
        flag_bytes = int(c).to_bytes(64, 'big')
        print(f"   Flag: {flag_bytes}")
    except Exception as e:
        print(f"\n⚠️ Error extracting flag: {e}")
        # Try alternative extraction
        # The vector representation in O
        print(f"   x_recovered = {x_recovered}")
        # Check if it's of form c*a where c is integer
        if hasattr(x_recovered, 'vector'):
            v = x_recovered.vector()
            print(f"   Vector: {v}")
