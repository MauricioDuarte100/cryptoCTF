#!/usr/bin/env python3
"""
crypto_always_has_been Solver
==============================

The hash uses flag as BOTH the key and data:
state = 0x00*32 XOR SecureCipher(flag).encrypt(flag)

So: hash = SecureCipher(flag).encrypt(flag)

We need to find flag such that this holds.

Key insight: The encryption is deterministic but involves 100 rounds 
of substitute-permute-XOR. 

The S-box depends on flag[0], so we can brute force flag[0] (256 values)
and then try to work backwards.

Actually, let's look at this differently:
- For each possible first byte of flag, we create the S-box
- Then we need to find what input produces the known output

Since both key and plaintext are the same (flag), this is a fixed-point 
style problem.
"""

KEY_SBOX = [170, 89, 81, 162, 65, 178, 186, 73, 97, 146, 154, 105, 138, 121, 113, 130, 33, 210, 218, 41, 202, 57, 49, 194, 234, 25, 17, 226, 1, 242, 250, 9, 161, 82, 90, 169, 74, 185, 177, 66, 106, 153, 145, 98, 129, 114, 122, 137, 42, 217, 209, 34, 193, 50, 58, 201, 225, 18, 26, 233, 10, 249, 241, 2, 188, 79, 71, 180, 87, 164, 172, 95, 119, 132, 140, 127, 156, 111, 103, 148, 55, 196, 204, 63, 220, 47, 39, 212, 252, 15, 7, 244, 23, 228, 236, 31, 183, 68, 76, 191, 92, 175, 167, 84, 124, 143, 135, 116, 151, 100, 108, 159, 60, 207, 199, 52, 215, 36, 44, 223, 247, 4, 12, 255, 28, 239, 231, 20, 134, 117, 125, 142, 109, 158, 150, 101, 77, 190, 182, 69, 166, 85, 93, 174, 13, 254, 246, 5, 230, 21, 29, 238, 198, 53, 61, 206, 45, 222, 214, 37, 141, 126, 118, 133, 102, 149, 157, 110, 70, 181, 189, 78, 173, 94, 86, 165, 6, 245, 253, 14, 237, 30, 22, 229, 205, 62, 54, 197, 38, 213, 221, 46, 144, 99, 107, 152, 123, 136, 128, 115, 91, 168, 160, 83, 176, 67, 75, 184, 27, 232, 224, 19, 240, 3, 11, 248, 208, 35, 43, 216, 59, 200, 192, 51, 155, 104, 96, 147, 112, 131, 139, 120, 80, 163, 171, 88, 187, 72, 64, 179, 16, 227, 235, 24, 251, 8, 0, 243, 219, 40, 32, 211, 48, 195, 203, 56]
PBOX = [59, 82, 101, 135, 189, 153, 105, 14, 179, 71, 167, 33, 160, 198, 218, 104, 66, 37, 216, 199, 132, 214, 217, 42, 231, 221, 236, 233, 203, 24, 220, 120, 158, 240, 84, 81, 152, 201, 57, 253, 249, 169, 79, 234, 136, 12, 40, 209, 29, 224, 17, 77, 60, 102, 195, 8, 212, 95, 147, 190, 138, 213, 98, 10, 4, 243, 1, 128, 145, 58, 241, 119, 88, 211, 110, 157, 3, 188, 19, 208, 44, 244, 122, 92, 109, 69, 134, 22, 90, 61, 202, 193, 141, 183, 133, 75, 144, 116, 191, 39, 207, 140, 192, 247, 83, 43, 121, 99, 254, 226, 177, 26, 9, 173, 78, 176, 223, 210, 156, 16, 227, 125, 93, 54, 76, 150, 5, 36, 185, 65, 72, 246, 131, 41, 106, 248, 151, 182, 204, 225, 229, 70, 7, 250, 115, 85, 163, 124, 184, 130, 239, 196, 15, 100, 252, 25, 171, 143, 0, 67, 222, 96, 165, 180, 46, 232, 117, 48, 38, 161, 50, 35, 73, 18, 154, 114, 175, 146, 148, 89, 80, 112, 228, 49, 172, 63, 123, 86, 149, 103, 230, 64, 28, 27, 166, 111, 170, 55, 47, 20, 51, 215, 32, 13, 118, 11, 53, 205, 238, 91, 6, 94, 200, 181, 162, 178, 194, 126, 164, 2, 255, 137, 242, 23, 74, 197, 142, 108, 52, 187, 129, 186, 155, 97, 107, 34, 245, 68, 56, 127, 21, 219, 159, 62, 113, 237, 206, 45, 251, 168, 87, 31, 30, 235, 174, 139]
BLOCK_SIZE = 32
xor = lambda a,b: bytes([b1 ^ b2 for b1, b2 in zip(a,b)])

# Compute inverse PBOX
INV_PBOX = [0] * 256
for i, v in enumerate(PBOX):
    INV_PBOX[v] = i

class SecureCipher:
    def __init__(self, key):
        self.sbox = [KEY_SBOX[i] ^ key[0] for i in range(256)]
        self.inv_sbox = [0] * 256
        for i, v in enumerate(self.sbox):
            self.inv_sbox[v] = i
        self.key = key
        
    def substitute(self, data):
        return bytes([self.sbox[b] for b in data])
    
    def inv_substitute(self, data):
        return bytes([self.inv_sbox[b] for b in data])
    
    def permute(self, data):
        out = [0]*32
        for num in range(256):
            outnum = PBOX[num]
            inbyte = num // 8
            inbit = 7 - (num % 8)
            outbyte = outnum // 8
            outbit = 7 - (outnum % 8)
            if data[inbyte] & (1 << inbit):
                out[outbyte] |= (1 << outbit)
        return bytes(out)
    
    def inv_permute(self, data):
        out = [0]*32
        for num in range(256):
            outnum = INV_PBOX[num]
            inbyte = num // 8
            inbit = 7 - (num % 8)
            outbyte = outnum // 8
            outbit = 7 - (outnum % 8)
            if data[inbyte] & (1 << inbit):
                out[outbyte] |= (1 << outbit)
        return bytes(out)
    
    def encrypt(self, data):
        block = data
        for _ in range(100):
            block = self.substitute(block)
            block = self.permute(block)
            block = xor(block, self.key)
        return block
    
    def decrypt(self, data):
        block = data
        for _ in range(100):
            block = xor(block, self.key)
            block = self.inv_permute(block)
            block = self.inv_substitute(block)
        return block


# Target hash
target_hash = bytes.fromhex("61b5649e894a15a053276c0dc828ee64ec2336f809e2dd7d2912c61c8ef02c26")

print("[*] crypto_always_has_been Solver")
print(f"[*] Target hash: {target_hash.hex()}")
print()

# The equation is: encrypt_key(key) = hash
# where key = flag = plaintext

# For a fixed first byte k0, the S-box is determined
# We can then decrypt the hash to get what the flag would need to be
# But the decrypted value must equal the key used... including k0!

print("[*] Brute forcing first byte of flag...")

for first_byte in range(256):
    # Create cipher with this first byte
    test_key = bytes([first_byte]) + b'\x00' * 31
    cipher = SecureCipher(test_key)
    
    # Decrypt the target hash
    decrypted = cipher.decrypt(target_hash)
    
    # Check if first byte matches
    if decrypted[0] == first_byte:
        print(f"\n[*] Found matching first byte: {first_byte} ({chr(first_byte) if 32 <= first_byte < 127 else '?'})")
        
        # Now we need to verify the full flag
        # Create cipher with the decrypted key
        cipher2 = SecureCipher(decrypted)
        
        # Encrypt the decrypted value as plaintext
        result = cipher2.encrypt(decrypted)
        
        if result == target_hash:
            print(f"\n[+] FOUND FLAG: {decrypted}")
            try:
                print(f"[+] FLAG (decoded): {decrypted.decode()}")
            except:
                print(f"[+] FLAG (hex): {decrypted.hex()}")
            exit(0)
        else:
            print(f"    Verification failed for {decrypted.hex()}")

print("\n[-] Simple brute force failed, trying iterative approach...")

# Alternative: Iterative fixed-point search
# Start with a guess and iterate: flag = decrypt_flag(hash)

print("[*] Trying iterative fixed-point approach...")

for start_byte in range(256):
    # Start with various initial guesses
    flag_guess = bytes([start_byte] * 32)
    
    for iteration in range(1000):
        cipher = SecureCipher(flag_guess)
        new_guess = cipher.decrypt(target_hash)
        
        # Check if we found a fixed point
        cipher2 = SecureCipher(new_guess)
        if cipher2.encrypt(new_guess) == target_hash:
            print(f"\n[+] FOUND FLAG at iteration {iteration}!")
            print(f"[+] FLAG: {new_guess}")
            try:
                print(f"[+] FLAG (decoded): {new_guess.decode()}")
            except:
                print(f"[+] FLAG (hex): {new_guess.hex()}")
            exit(0)
        
        flag_guess = new_guess
    
    if start_byte % 32 == 0:
        print(f"  Tried starting bytes 0-{start_byte}...")

print("\n[-] All approaches failed")
