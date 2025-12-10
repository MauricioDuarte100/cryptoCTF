"""
Solver for leaky.txt - Deep Analysis of Partial Signatures

The Bellcore attack failed. Let's explore other interpretations:
1. s1, s2 might be CRT components (sp, sq) that can be combined
2. The message might need padding (PKCS#1)
3. The signatures might use dp, dq instead of d
"""

from math import gcd, isqrt
from Crypto.Util.number import long_to_bytes, bytes_to_long
import hashlib

n = 20165334194765235320424366746152716277217335167739011687018268583510493207127112328669960881954898516215328757802317213059027338326521290670211213873391567748843927403892866188134339713257446303844707076817749820392498183538026039282123839854002077503379772733696886024283586023811431231839828651203299985411138322418280967881818779030920671726679828610445706176683015972092453253603946164834126812789217998766870274626068175342739777467580762724206081323810782182042226761228438554723601033894009929289994831994346726933258698476285286359654373777591031445217562231194946563145193522602431103703113263165226877860253
e = 65537
c = 2118456137965994841247536020622311777803911835103734822064766812876721933583814091023966719923605975270460808176348946988766550158503862702248480984874075046027663162433361253503928216983249895708514933854119017451000951193008302008684696480942487339168319938331657233626554733546983832719863439888353721857859430827032846169768185387264381510968933639081396032329395593271985065536740399294613396614952763769484978328336972808938535704714463312398101677308696651536113029547437658083836868884321523656200715989806567461762800390648813872667795999299709984253419486784578362945626566625939609023481854031908155033379
msg = b'an arbitrary message'
s1 = 95678458388745250423760905503280483222097368310747202630759262308378549131107656889012109648043084464019046718566073898163672344101935457525871808354976189789555547903446995010771592456826112994514652291892824071596551320313778230218688892542007942856995285456098483325124412919854380430160711429719581943186
s2 = 44547475025831656355528127852589231568747746095699542039872933478095639258629729532836327687584576126088247623864664501427420859769572510905581856911584688335854740368478089560073177291163952918219526397369017609904356324387337763600288101616490251360830613106875247954884693272527289066375679738039998985649

print("🔓 Leaky RSA Deep Analysis")
print("=" * 60)

# Convert message to integer
m_raw = bytes_to_long(msg)
print(f"\n📊 Message as raw integer: {m_raw}")
print(f"   Message bytes: {msg}")

# Try SHA-256 hash of message (common in RSA signatures)
m_sha256 = bytes_to_long(hashlib.sha256(msg).digest())
print(f"\n📊 Message as SHA-256: {m_sha256}")

# Try MD5 hash
m_md5 = bytes_to_long(hashlib.md5(msg).digest())
print(f"📊 Message as MD5: {m_md5}")

# Check s1^e and s2^e
s1_e = pow(s1, e, n)
s2_e = pow(s2, e, n)

print(f"\n📊 Signature verification:")
print(f"   s1^e mod n = {s1_e}")
print(f"   s2^e mod n = {s2_e}")

# Check if they equal any of the message variants
for name, m in [("raw", m_raw), ("sha256", m_sha256), ("md5", m_md5)]:
    if s1_e == m:
        print(f"   ✅ s1^e = {name}")
    if s2_e == m:
        print(f"   ✅ s2^e = {name}")

# Check GCDs with different message encodings
print("\n🔍 GCD Analysis with different message encodings:")
for name, m in [("raw", m_raw), ("sha256", m_sha256), ("md5", m_md5)]:
    g1 = gcd(s1_e - m, n)
    g2 = gcd(s2_e - m, n)
    print(f"   {name}: gcd(s1^e - m, n) = {g1}, gcd(s2^e - m, n) = {g2}")
    
    if g1 not in [1, n]:
        print(f"   ✅ Found factor p = {g1} using s1 and {name}!")
        p = g1
        q = n // p
        break
    if g2 not in [1, n]:
        print(f"   ✅ Found factor q = {g2} using s2 and {name}!")
        p = g2
        q = n // p
        break
else:
    print("\n❌ Standard message encodings didn't work")
    
    # Try PKCS#1 v1.5 padding pattern
    # For SHA-256: DigestInfo prefix is 0x3031300d060960864801650304020105000420
    sha256_digest = hashlib.sha256(msg).digest()
    pkcs1_prefix = bytes.fromhex('3031300d060960864801650304020105000420')
    
    # PKCS#1 v1.5: 0x00 0x01 [FF padding] 0x00 [DigestInfo + Hash]
    # The padded message length equals n's byte length
    n_byte_len = (n.bit_length() + 7) // 8
    
    digest_info = pkcs1_prefix + sha256_digest
    padding_len = n_byte_len - 3 - len(digest_info)
    if padding_len > 0:
        pkcs1_padded = b'\x00\x01' + b'\xff' * padding_len + b'\x00' + digest_info
        m_pkcs1 = bytes_to_long(pkcs1_padded)
        
        print(f"\n🔍 Trying PKCS#1 v1.5 padded message:")
        g1 = gcd(s1_e - m_pkcs1, n)
        g2 = gcd(s2_e - m_pkcs1, n)
        print(f"   gcd(s1^e - m_pkcs1, n) = {g1}")
        print(f"   gcd(s2^e - m_pkcs1, n) = {g2}")
        
        if g1 not in [1, n]:
            p = g1
            q = n // p
            print(f"   ✅ Found factor!")
        elif g2 not in [1, n]:
            p = g2
            q = n // p
            print(f"   ✅ Found factor!")

# Alternative: CRT combination attack
print("\n🔍 Trying CRT combination attack...")
# If s1 and s2 are sp and sq (CRT components), we can try to reconstruct s
# s = s1 * qinv * q + s2 * pinv * p (mod n)
# But we don't know p and q...

# However, if s1 ≡ m^d (mod p) and s2 ≡ m^d (mod q), then:
# gcd(s1 - s2, n) might give useful info when combined with other equations

# Try: s1 * s2 approach
s_prod = (s1 * s2) % n
print(f"   s1 * s2 mod n = {s_prod}")

# If s1 = m^d mod p and s2 = m^d mod q (as CRT halves):
# Then s1 * s2 ≢ m^(2d) in general

# Try: s1 + s2 approach
s_sum = (s1 + s2) % n
print(f"   s1 + s2 mod n = {s_sum}")

# Check if s1 and s2 satisfy: s1 ≡ s2 (mod something small)
for small_prime in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31]:
    if s1 % small_prime == s2 % small_prime:
        print(f"   s1 ≡ s2 (mod {small_prime})")

# Lattice-based attack: If we have:
# s1 = m^d + k1*p for some k1
# s2 = m^d + k2*q for some k2
# Then s1 - s2 = k1*p - k2*q
# And: n = p*q, so we can set up a lattice...

print("\n🔍 Lattice-style analysis...")
# gcd(s1 - s2, n) should give a non-trivial factor if aligned properly
diff = abs(s1 - s2)
g_diff = gcd(diff, n)
print(f"   gcd(|s1 - s2|, n) = {g_diff}")

# Try: gcd(s1^2 - s2^2, n) = gcd((s1-s2)(s1+s2), n)
g_diff_sq = gcd(s1**2 - s2**2, n)
print(f"   gcd(s1^2 - s2^2, n) = {g_diff_sq}")

# Check: maybe the signatures are related by multiplication
# s1 = a * s2 mod n for some a?
# Then s1 * s2^(-1) mod n = a
s2_inv = pow(s2, -1, n)
ratio = (s1 * s2_inv) % n
print(f"   s1 / s2 mod n = {ratio}")
print(f"   ratio bits: {ratio.bit_length()}")

# Check if ratio is smooth or has special form
g_ratio = gcd(ratio - 1, n)
print(f"   gcd(ratio - 1, n) = {g_ratio}")
g_ratio_plus = gcd(ratio + 1, n)
print(f"   gcd(ratio + 1, n) = {g_ratio_plus}")

if g_ratio not in [1, n]:
    print(f"\n✅ Found factor from ratio - 1!")
    p = g_ratio
    q = n // p
elif g_ratio_plus not in [1, n]:
    print(f"\n✅ Found factor from ratio + 1!")
    p = g_ratio_plus
    q = n // p

# Final check: Maybe the "partial" means something simpler
# Like s1, s2 are signatures of two different but related messages?
print("\n🔍 Checking if s1, s2 are for related messages...")

# If s1 = m1^d and s2 = m2^d where m1 + m2 = something known
# then s1^e = m1, s2^e = m2

m1 = s1_e
m2 = s2_e
print(f"   m1 = s1^e mod n = {m1}")
print(f"   m2 = s2^e mod n = {m2}")

# Check if m1 and m2 are related
print(f"   m1 + m2 mod n = {(m1 + m2) % n}")
print(f"   m1 - m2 mod n = {(m1 - m2) % n}")
print(f"   gcd(m1 - m_raw, n) = {gcd(m1 - m_raw, n)}")
print(f"   gcd(m2 - m_raw, n) = {gcd(m2 - m_raw, n)}")

# If any of the above found a factor, decrypt
if 'p' in dir() and 'q' in dir():
    print(f"\n📊 Factorization successful!")
    print(f"   p = {p}")
    print(f"   q = {q}")
    print(f"   p * q == n: {p * q == n}")
    
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    plaintext_int = pow(c, d, n)
    plaintext = long_to_bytes(plaintext_int)
    print(f"\n🚩 FLAG: {plaintext}")
else:
    print("\n❌ Could not factor n with standard attacks")
    print("   Need more sophisticated approach...")
