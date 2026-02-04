"""
Real Number Generator - Analysis and LCG reduction attack

The RNG is:
    state = D(e) * D(state) % D(pi)
    r = sqrt(|sin(float(state)) + cos(float(state))|)

Key observation:
    D(e) and D(pi) are fixed 28-digit approximations.
    The operation is essentially: state_{n+1} = a * state_n mod m
    where a = D(e) and m = D(pi)

This is a Linear Congruential Generator (LCG) over Decimals!

But wait - the state is continuous, not discrete.
For integer seeds, let's see what happens:

seed (integer) -> D(seed) (exact) -> D(e) * D(seed) -> mod D(pi)

The result is a Decimal with up to 28 significant digits.

New insight: Maybe we can use Z3 or SAT solver to find the seed
by encoding the constraints from the known keystream bytes.
"""

import struct
import math
import hashlib
from decimal import getcontext, Decimal as D

getcontext().prec = 28

xor = lambda A, B: bytes([a ^ b for a, b in zip(A, B)])

# From output.txt
enc_hex = "1040d2bac7d79358f28394ea658ed37a4aa13f3c1921415429c232034aa73c5431051d0e36d1dbf0ae5dbdf920eb1755f48a"
enc = bytes.fromhex(enc_hex)

known_prefix = b"The flag is: "
keystream = xor(enc, known_prefix)

first_r = struct.unpack('d', keystream[:8])[0]
print(f"[*] First random value r = {first_r}")

# The constraint is: for some integer seed in [0, 2^48),
# compute state = D(e) * D(seed) % D(pi)
# then r = sqrt(|sin(float(state)) + cos(float(state))|) == first_r

# Since r is a double, it has limited precision (~15-17 significant digits).
# Many states map to the same r value.

# Let's understand the structure better.

# sin(x) + cos(x) = sqrt(2) * sin(x + pi/4)
# |sin(x) + cos(x)| = sqrt(2) * |sin(x + pi/4)|
# r^2 = sqrt(2) * |sin(state + pi/4)|

r2 = first_r ** 2
sin_val = r2 / math.sqrt(2)
print(f"[*] r^2 = {r2}")
print(f"[*] |sin(state + pi/4)| = {sin_val}")

# state + pi/4 = arcsin(sin_val) or pi - arcsin(sin_val) or related angles

if sin_val <= 1:
    base_angle = math.asin(sin_val)
    print(f"[*] arcsin({sin_val}) = {base_angle}")
    
    # The state could be any of these (mod 2*pi):
    # state = base_angle - pi/4
    # state = pi - base_angle - pi/4
    # And their negatives for the abs()
    
    candidates = [
        base_angle - math.pi/4,
        math.pi - base_angle - math.pi/4,
        -base_angle - math.pi/4,
        math.pi + base_angle - math.pi/4,
    ]
    
    # Normalize to [0, pi) since state = e*seed mod pi is in [0, pi)
    normalized = []
    for c in candidates:
        c_norm = c % (2 * math.pi)
        if 0 <= c_norm < math.pi:
            normalized.append(c_norm)
    
    normalized = list(set([round(x, 15) for x in normalized]))
    print(f"[*] Candidate states in [0, pi): {normalized}")
    
    # For each candidate state, we need to find integer seed such that:
    # D(e) * D(seed) % D(pi) is close to state
    
    # The key is that D(e) and D(pi) are specific values.
    E = D(str(math.e))  # 2.718281828459045...
    PI = D(str(math.pi))  # 3.141592653589793...
    
    print(f"\n[*] Decimal e = {E}")
    print(f"[*] Decimal pi = {PI}")
    
    # For seed s (integer), state = (E * s) % PI
    # We want state ≈ target_state
    # So E * s ≈ target_state + k * PI for some integer k ≥ 0
    # s ≈ (target_state + k * PI) / E
    
    # Since s must be an integer, we check floor and ceil of this value.
    
    def full_check_seed(seed):
        state = D(seed)
        state = E * state % PI
        r = math.sqrt(math.fabs(math.sin(float(state)) + math.cos(float(state))))
        return struct.pack('d', r) == keystream[:8]
    
    def decrypt_with_seed(seed):
        state = D(seed)
        ks = []
        while len(ks) < len(enc):
            state = E * state % PI
            r = math.sqrt(math.fabs(math.sin(float(state)) + math.cos(float(state))))
            ks.extend(struct.pack('d', r))
        
        msg = xor(enc, bytes(ks[:len(enc)]))
        if msg[:len(known_prefix)] != known_prefix:
            return None
        
        flag_enc = msg[len(known_prefix):]
        flag = xor(flag_enc, hashlib.shake_256(str(seed).encode()).digest(len(flag_enc)))
        return flag
    
    print("\n[*] Searching for seeds...")
    
    max_seed = 2**48
    found = False
    
    for target_state in normalized:
        if found:
            break
            
        target = D(str(target_state))
        print(f"\n[*] Target state = {target_state}")
        
        # For k from 0 upwards, compute candidate seed
        # s = (target + k * PI) / E
        k = 0
        checked = 0
        while not found:
            seed_dec = (target + D(k) * PI) / E
            
            seed_int = int(seed_dec)
            if seed_int >= max_seed:
                break
            
            if seed_int >= 0:
                # Check this seed
                if full_check_seed(seed_int):
                    print(f"\n[+] FOUND SEED: {seed_int}")
                    found = True
                    flag = decrypt_with_seed(seed_int)
                    if flag:
                        try:
                            print(f"\n{'='*60}")
                            print(f"   FLAG: {flag.decode()}")
                            print(f"{'='*60}")
                        except:
                            print(f"   FLAG (bytes): {flag}")
                    break
                
                # Also check seed_int + 1 due to rounding
                if full_check_seed(seed_int + 1):
                    print(f"\n[+] FOUND SEED: {seed_int + 1}")
                    found = True
                    flag = decrypt_with_seed(seed_int + 1)
                    if flag:
                        try:
                            print(f"\n{'='*60}")
                            print(f"   FLAG: {flag.decode()}")
                            print(f"{'='*60}")
                        except:
                            print(f"   FLAG (bytes): {flag}")
                    break
                
                checked += 2
            
            k += 1
            
            if k % 1000000 == 0:
                print(f"    k = {k}, seed ≈ {seed_int}")
            
            if k > 10**8:  # Limit to 100M k values per state
                break
    
    if not found:
        print("\n[!] Seed not found with analytical approach.")
        print("[*] The seed might be larger than expected or there's a precision issue.")
