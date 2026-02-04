from Crypto.Util.number import long_to_bytes
import gmpy2

# Challenge data
n = 91102717210596990388603678426683097953697889897819753293818443119019220403217013812232251320814152567699322671590559119510246139859891156830672838769529887961956970370968572962306584295059185945752892892100975462391203805852473243296747559459800718013816237662990504689724747628304890125129146326331097856907
c1 = 84316690833236468829386139306045298111202426584048821548102362931269993141514516100633466389955824290011995159677864206138653174440904170622039293036862729884826231898868928186453091113165643576890891297150845933751243965934735328928976655465009980896153972226679588496970771925581698573227941539852081781874
c2 = 74682069306151159606579889187354529286195652598555930926994495384029865435810129236911316774977007932641783161876484392995815937986886903514990618178943843429073696833993271982336114314882872652681858748846455760309012235191324385691614015531641062111894149446939460102878320469041435024347449132388644171970
e1 = 65517
e2 = 65577

# Extended GCD
def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    gcd_val, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd_val, x, y

g, a, b = extended_gcd(e1, e2)
print(f"gcd = {g}, a = {a}, b = {b}")

# Compute m^g mod n
if a < 0:
    c1_inv = gmpy2.invert(c1, n)
    m_cubed = (pow(int(c1_inv), -a, n) * pow(c2, b, n)) % n
elif b < 0:
    c2_inv = gmpy2.invert(c2, n)
    m_cubed = (pow(c1, a, n) * pow(int(c2_inv), -b, n)) % n
else:
    m_cubed = (pow(c1, a, n) * pow(c2, b, n)) % n

print(f"m^3 mod n = {m_cubed}")

# The message structure:
# padded_flag = long_to_bytes(n)[:-len(flag)] + flag.encode()
# m = bytes_to_long(padded_flag)
# Let flag_len be the length of the flag (unknown, but <= 40).
# Let n_bytes = long_to_bytes(n).
# high_part = n_bytes[:-flag_len] = long_to_bytes(n >> (8*flag_len))
# m = (n >> (8*flag_len)) << (8*flag_len) + flag_int
# Let k = n >> (8*flag_len), then m = k * 256^flag_len + x, where x = flag_int.
# m^3 = (k * 2^(8*flag_len) + x)^3 mod n
# We have m^3 mod n = m_cubed.
# x is small (< 256^flag_len).
# This is a Coppersmith small roots problem.

# Brute force over flag_len from 1 to 40.
# For each flag_len, compute k and check if x can be found.

n_bytes = long_to_bytes(n)
print(f"n has {len(n_bytes)} bytes.")

for flag_len in range(14, 41): # Typical flag length like Alpaca{...}
    shift = 8 * flag_len
    k = n >> shift
    base = k << shift
    
    # m = base + x, where 0 <= x < 2^shift
    # m^3 = m_cubed mod n
    # (base + x)^3 = m_cubed mod n
    
    # Let's try to solve this directly.
    # Expand: (base + x)^3 = base^3 + 3*base^2*x + 3*base*x^2 + x^3
    # This is a cubic in x modulo n.
    
    # We can try Coppersmith via Sympy/Sage, but let's first try a direct approach.
    # Since x is small (flag_len <= 40 bytes = 320 bits), x < 2^320.
    # n is 1024 bits. For Coppersmith, we need x < n^(1/3) = ~341 bits.
    # This is on the edge, but might work.
    
    # Let's try a different approach: Newton's method / Hensel lifting.
    # Or brute force for very short flags (flag_len < 16).
    
    # For now, let's check if the base is correct by checking the MSBs of m.
    # If m = base + x, then m > base and m < base + 2^shift.
    # m^3 mod n = m_cubed.
    # If base is correct, (base + x)^3 = m_cubed (mod n).
    
    # Let's check modular arithmetic.
    # (base + x)^3 - m_cubed = 0 (mod n)
    
    pass

# Approach: Use Newton-Raphson to find x.
# f(x) = (base + x)^3 - m_cubed mod n
# f'(x) = 3*(base + x)^2
# Newton: x_new = x - f(x)/f'(x)

# But this is complex in modular arithmetic. Let's try a simpler approach.
# Since m is roughly n (same MSBs), m^3 >> n.
# Let m = n - delta, where delta is small (delta = n - m = n - (n_high || flag)).
# delta = n - k*2^shift - x = n - n_high*2^shift - x = (n mod 2^shift) - x
# delta = (n & ((1 << shift) - 1)) - x

# m^3 = (n - delta)^3 = n^3 - 3n^2*delta + 3n*delta^2 - delta^3
# mod n: m^3 ≡ -3n^2*delta + 3n*delta^2 - delta^3 ≡ 0 - 0 - delta^3 = -delta^3 (mod n)
# Wait, 3n^2*delta mod n = 0, 3n*delta^2 mod n = 0.
# So m^3 ≡ -delta^3 (mod n).
# m_cubed ≡ -delta^3 (mod n).
# delta^3 ≡ -m_cubed (mod n).

delta_cubed = (-m_cubed) % n
print(f"delta^3 mod n = {delta_cubed}")

# Now we need to find delta such that delta^3 = delta_cubed.
# Since delta = (n mod 2^shift) - x, and x is the flag.
# delta is small if flag_len is small.

# Check if delta_cubed is a perfect cube.
delta, is_perf = gmpy2.iroot(delta_cubed, 3)
if is_perf:
    print(f"Perfect cube! delta = {delta}")
    # delta = (n & mask) - x
    # We need to brute force flag_len.
    for flag_len in range(10, 41):
        mask = (1 << (8 * flag_len)) - 1
        n_low = n & mask
        x = n_low - int(delta)
        if 0 < x < (1 << (8 * flag_len)):
            flag_bytes = long_to_bytes(x)
            try:
                flag_str = flag_bytes.decode()
                if flag_str.startswith("Alpaca{") or flag_str.startswith("FLAG{") or flag_str.startswith("flag{"):
                    print(f"Flag (flag_len={flag_len}): {flag_str}")
                    break
                elif all(32 <= ord(c) <= 126 for c in flag_str):
                    print(f"Possible (flag_len={flag_len}): {flag_str}")
            except:
                pass
else:
    print("delta^3 is not a perfect cube. Trying brute force for k...")
    for k in range(10000):
        val = delta_cubed + k * n
        root, is_p = gmpy2.iroot(val, 3)
        if is_p:
            delta = int(root)
            print(f"Found delta at k={k}: {delta}")
            # Try to recover flag
            for flag_len in range(10, 41):
                mask = (1 << (8 * flag_len)) - 1
                n_low = n & mask
                x = n_low - delta
                if 0 < x < (1 << (8 * flag_len)):
                    flag_bytes = long_to_bytes(x)
                    try:
                        flag_str = flag_bytes.decode()
                        if "Alpaca{" in flag_str or "flag{" in flag_str.lower():
                            print(f"Flag: {flag_str}")
                            exit()
                        elif all(32 <= ord(c) <= 126 for c in flag_str):
                            print(f"Possible: {flag_str}")
                    except:
                        pass
            break
    else:
        print("Brute force for delta failed.")
