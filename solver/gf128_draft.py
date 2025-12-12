import struct

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def bytes_to_long(b):
    return int.from_bytes(b, 'big')

def long_to_bytes(l):
    return l.to_bytes(16, 'big')

# GCM Polynomial Representation:
# defined by P(x) = x^128 + x^7 + x^2 + x + 1
# However, GCM uses a specific bit order (little endian for bits in byte? no, distinct).
# We will trust the existing 'mul' implementation from the challenge or reimplement standard GCM mul.
# The challenge gcm.py mul seems to implement the standard.

# We will treat 128-bit blocks as elements in GF(2^128).
# Representation: integer.

R = 0xE1 << (120) # This is roughly x^128 etc shifted?
# Actually checking challenge mul:
# R = bytes_to_bits(b"\xe1" + b"\x00"*15)
# This corresponds to the GCM reduction polynomial.

class GF128:
    def __init__(self, val):
        if isinstance(val, bytes):
            self.val = bytes_to_long(val)
        else:
            self.val = val

    def __add__(self, other):
        return GF128(self.val ^ other.val)
    
    def __sub__(self, other):
        return self + other

    def __eq__(self, other):
        return self.val == other.val

    def __mul__(self, other):
        # Standard GCM multiplication
        # We can implement it using the integer based logic for speed
        x = self.val
        y = other.val
        z = 0
        v = y
        # R = 0xe10000...0000 (128 bits)
        # Shifted correctly: standard GCM reverses bits usually, but let's stick to the challenge implementation logic if possible.
        # But challenge uses "bytes_to_bits" and list of bits. Very slow.
        # We need a faster one.
        
        # Optimized GCM mul for standard GCM bit order (GCM is weird, LSB first for polynomial coefficients).
        # Let's try to match challenge logic:
        # Challenge 'mul(X, Y)':
        # X, Y are bytes.
        # Z = 0
        # for i in range(128):
        #    if bit i of X is 1: Z ^= V
        #    if bit 127 of V is 0: V >>= 1
        #    else: V = (V >> 1) ^ (0xE1 << 120)
        # This matches standard GCM if bits are considered correctly.
        
        # Let's use the standard integer implementation:
        for i in range(128):
            # Check if i-th bit of x is set. 
            # In challenge: 'X = bytes_to_bits(X)' means X[0] is MSB of first byte?
            # bytes_to_bits: b'\x80' -> [1,0,0,0...]
            # So X[0] is MSB.
            if (x >> (127 - i)) & 1:
                z ^= v
            
            if v & 1:
                v = (v >> 1) ^ (0xE1 << 120) 
            else:
                v >>= 1
        return GF128(z)

    def to_bytes(self):
        return long_to_bytes(self.val)
        
    def inv(self):
        # Power(a, 2^128 - 2)
        exponent = (1 << 128) - 2
        res = GF128(1 << 127) # Is 1 represented as 1<<127 or 1?
        # In GCM, "1" is 0x8000...00. i.e. MSB set?
        # No, 1 is just the integer 1 if we map correctly.
        # Let's verify: mul(1, A) should be A.
        # if x = 1 (0...01).
        # Loop i=127: (x>>0)&1 -> 1. z^=v.
        # v has been shifted 127 times.
        # This seems sensitive to representation.
        
        # Let's stick to the REFERENCE implementation provided in challenge.
        # It's safest.
        return GF128(1) # Todo

# Actually, reusing the challenge code is strictly safer to avoid endianness mismatch.
# I will copy the 'mul' from gcm/gcm.py exactly but optimize it for integers? 
# No, let's just copy the python logic.

class Poly:
    def __init__(self, coeffs):
        # coeffs[0] is high degree, coeffs[-1] is const (x^0)
        self.coeffs = coeffs # List of GF128 elements

    def __add__(self, other):
        # Pad with zeros
        n = max(len(self.coeffs), len(other.coeffs))
        a = [GF128(0)] * (n - len(self.coeffs)) + self.coeffs
        b = [GF128(0)] * (n - len(other.coeffs)) + other.coeffs
        return Poly([x + y for x, y in zip(a, b)])

    def degree(self):
        return len(self.coeffs) - 1

    def __repr__(self):
        return f"Poly(deg={self.degree()})"
