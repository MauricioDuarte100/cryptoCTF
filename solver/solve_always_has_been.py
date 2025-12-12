#!/usr/bin/env python3
"""
Final solver for crypto_always_has_been

After much analysis, let's try a different approach:
The hash uses Davies-Meyer construction variant:
  state = state XOR encrypt(block) where key=block

The weakness: encrypt(x, x) = hash means we're looking for a preimage.
For the specific case where data = key, the cipher has a special structure.

Key observation: After 100 rounds of the same operation, we need:
  round_100(x) = hash for the transformation round(x) = xor(permute(sbox(x)), x)

This is a FUNCTIONAL equation. The function round depends on x itself (through the XOR).

Let's try EVERY possible flag format more systematically:
1. CCTF{...} - 5+26+1 = 32 bytes - 26 unknown
2. Actually, test if any common 32-byte patterns match
"""

KEY_SBOX = [170, 89, 81, 162, 65, 178, 186, 73, 97, 146, 154, 105, 138, 121, 113, 130, 33, 210, 218, 41, 202, 57, 49, 194, 234, 25, 17, 226, 1, 242, 250, 9, 161, 82, 90, 169, 74, 185, 177, 66, 106, 153, 145, 98, 129, 114, 122, 137, 42, 217, 209, 34, 193, 50, 58, 201, 225, 18, 26, 233, 10, 249, 241, 2, 188, 79, 71, 180, 87, 164, 172, 95, 119, 132, 140, 127, 156, 111, 103, 148, 55, 196, 204, 63, 220, 47, 39, 212, 252, 15, 7, 244, 23, 228, 236, 31, 183, 68, 76, 191, 92, 175, 167, 84, 124, 143, 135, 116, 151, 100, 108, 159, 60, 207, 199, 52, 215, 36, 44, 223, 247, 4, 12, 255, 28, 239, 231, 20, 134, 117, 125, 142, 109, 158, 150, 101, 77, 190, 182, 69, 166, 85, 93, 174, 13, 254, 246, 5, 230, 21, 29, 238, 198, 53, 61, 206, 45, 222, 214, 37, 141, 126, 118, 133, 102, 149, 157, 110, 70, 181, 189, 78, 173, 94, 86, 165, 6, 245, 253, 14, 237, 30, 22, 229, 205, 62, 54, 197, 38, 213, 221, 46, 144, 99, 107, 152, 123, 136, 128, 115, 91, 168, 160, 83, 176, 67, 75, 184, 27, 232, 224, 19, 240, 3, 11, 248, 208, 35, 43, 216, 59, 200, 192, 51, 155, 104, 96, 147, 112, 131, 139, 120, 80, 163, 171, 88, 187, 72, 64, 179, 16, 227, 235, 24, 251, 8, 0, 243, 219, 40, 32, 211, 48, 195, 203, 56]
PBOX = [59, 82, 101, 135, 189, 153, 105, 14, 179, 71, 167, 33, 160, 198, 218, 104, 66, 37, 216, 199, 132, 214, 217, 42, 231, 221, 236, 233, 203, 24, 220, 120, 158, 240, 84, 81, 152, 201, 57, 253, 249, 169, 79, 234, 136, 12, 40, 209, 29, 224, 17, 77, 60, 102, 195, 8, 212, 95, 147, 190, 138, 213, 98, 10, 4, 243, 1, 128, 145, 58, 241, 119, 88, 211, 110, 157, 3, 188, 19, 208, 44, 244, 122, 92, 109, 69, 134, 22, 90, 61, 202, 193, 141, 183, 133, 75, 144, 116, 191, 39, 207, 140, 192, 247, 83, 43, 121, 99, 254, 226, 177, 26, 9, 173, 78, 176, 223, 210, 156, 16, 227, 125, 93, 54, 76, 150, 5, 36, 185, 65, 72, 246, 131, 41, 106, 248, 151, 182, 204, 225, 229, 70, 7, 250, 115, 85, 163, 124, 184, 130, 239, 196, 15, 100, 252, 25, 171, 143, 0, 67, 222, 96, 165, 180, 46, 232, 117, 48, 38, 161, 50, 35, 73, 18, 154, 114, 175, 146, 148, 89, 80, 112, 228, 49, 172, 63, 123, 86, 149, 103, 230, 64, 28, 27, 166, 111, 170, 55, 47, 20, 51, 215, 32, 13, 118, 11, 53, 205, 238, 91, 6, 94, 200, 181, 162, 178, 194, 126, 164, 2, 255, 137, 242, 23, 74, 197, 142, 108, 52, 187, 129, 186, 155, 97, 107, 34, 245, 68, 56, 127, 21, 219, 159, 62, 113, 237, 206, 45, 251, 168, 87, 31, 30, 235, 174, 139]

INV_PBOX = [0] * 256
for i, v in enumerate(PBOX):
    INV_PBOX[v] = i

xor = lambda a, b: bytes([b1 ^ b2 for b1, b2 in zip(a, b)])


def permute(data):
    out = [0] * 32
    for num in range(256):
        outnum = PBOX[num]
        inbyte = num // 8
        inbit = 7 - (num % 8)
        outbyte = outnum // 8
        outbit = 7 - (outnum % 8)
        if data[inbyte] & (1 << inbit):
            out[outbyte] |= (1 << outbit)
    return bytes(out)


def inv_permute(data):
    out = [0] * 32
    for num in range(256):
        src = INV_PBOX[num]
        inbyte = num // 8
        inbit = 7 - (num % 8)
        outbyte = src // 8
        outbit = 7 - (src % 8)
        if data[inbyte] & (1 << inbit):
            out[outbyte] |= (1 << outbit)
    return bytes(out)


def encrypt(data, key):
    sbox = [KEY_SBOX[i] ^ key[0] for i in range(256)]
    block = bytes(data)
    for _ in range(100):
        block = bytes([sbox[b] for b in block])
        block = permute(block)
        block = xor(block, key)
    return block


def decrypt(data, key):
    sbox = [KEY_SBOX[i] ^ key[0] for i in range(256)]
    inv_sbox = [0] * 256
    for i, v in enumerate(sbox):
        inv_sbox[v] = i
    
    block = bytes(data)
    for _ in range(100):
        block = xor(block, key)
        block = inv_permute(block)
        block = bytes([inv_sbox[b] for b in block])
    return block


def solve_with_iteration_all_starts():
    """
    Try iteration from multiple starting points.
    For each possible first byte, start from that and a random rest,
    and iterate until convergence or cycle.
    """
    hash_hex = "61b5649e894a15a053276c0dc828ee64ec2336f809e2dd7d2912c61c8ef02c26"
    target = bytes.fromhex(hash_hex)
    
    import random
    
    print(f"[*] Target: {hash_hex}")
    print(f"[*] Trying many random starting points...")
    
    random.seed(42)
    found = False
    
    for attempt in range(10000):
        # Random 32-byte key
        key = bytes([random.randint(0, 255) for _ in range(32)])
        
        seen = set()
        for iteration in range(1000):
            key_hex = key.hex()
            if key_hex in seen:
                break  # Cycle
            seen.add(key_hex)
            
            # Decrypt target with current key
            plaintext = decrypt(target, key)
            
            # Check if it's the fixed point
            if plaintext == key:
                test = encrypt(plaintext, plaintext)
                if test == target:
                    print(f"\n[+] FOUND! Attempt {attempt}, iteration {iteration}")
                    print(f"[+] Flag (hex): {plaintext.hex()}")
                    try:
                        print(f"[+] Flag: {plaintext.decode()}")
                    except:
                        pass
                    return plaintext
            
            key = plaintext
        
        if attempt % 1000 == 0:
            print(f"[*] Attempt {attempt}...")
    
    return None


def solve_z3_simplified():
    """
    Use z3 to solve a simplified version of the problem.
    We'll model the first few bits to see if there's a structure we can exploit.
    """
    print("[-] Z3 approach skipped (too complex for 100 rounds)")
    return None


def main():
    print("[*] Crypto Always Has Been - Final Solver")
    print()
    
    result = solve_with_iteration_all_starts()
    if result:
        return result
    
    print()
    result = solve_z3_simplified()
    if result:
        return result
    
    print()
    print("[-] Could not find solution")
    print("[*] This challenge may require more specialized techniques:")
    print("    - SageMath algebraic analysis")
    print("    - GPU-accelerated search")
    print("    - Analysis of the specific SBOX/PBOX structure")
    
    return None


if __name__ == "__main__":
    result = main()
    if result:
        print(f"\n[SUCCESS] Flag: {result}")
    else:
        print(f"\n[FAILED]")
