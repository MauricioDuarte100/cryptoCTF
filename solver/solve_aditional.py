#!/usr/bin/env python3
"""
Solver for DGHV Homomorphic Encryption Challenge
archive.cryptohack.org:21970

The vulnerability: 
- Flag is encrypted with N=128, giving us flag_char mod 128
- We can encrypt zeros with different N values and add to ciphertext
- This gives us flag_char mod N for different N values
- Using CRT with coprimes, we can recover the original character

Attack:
1. Get encrypted flag (gives c_i where decrypt gives flag[i] mod 128)
2. For each position, use the "add" feature with N coprime to 128
3. Decrypt to get flag[i] mod N
4. Use CRT to combine and recover flag[i]
"""

import socket
from math import gcd
from functools import reduce

HOST = "archive.cryptohack.org"
PORT = 21970

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    gcd_val, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd_val, x, y

def chinese_remainder_theorem(residues, moduli):
    """Solve x ≡ r_i (mod m_i) for all i"""
    if len(residues) != len(moduli):
        raise ValueError("Lists must have same length")
    
    # Product of all moduli
    M = reduce(lambda a, b: a * b, moduli)
    
    result = 0
    for r_i, m_i in zip(residues, moduli):
        M_i = M // m_i
        _, x, _ = extended_gcd(M_i, m_i)
        result += r_i * M_i * x
    
    return result % M

def get_coprimes_in_range(start, end, existing):
    """Find values coprime to all existing values in range [start, end)"""
    coprimes = []
    for n in range(start, end):
        if all(gcd(n, e) == 1 for e in existing):
            coprimes.append(n)
    return coprimes

class DGHVSolver:
    def __init__(self, host, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host, port))
        self.buffer = b""
        
    def recv_until(self, delimiter):
        while delimiter not in self.buffer:
            data = self.sock.recv(4096)
            if not data:
                break
            self.buffer += data
        idx = self.buffer.find(delimiter)
        if idx != -1:
            result = self.buffer[:idx + len(delimiter)]
            self.buffer = self.buffer[idx + len(delimiter):]
            return result.decode()
        return self.buffer.decode()
    
    def recv_all_available(self, timeout=1):
        """Receive all available data"""
        self.sock.settimeout(timeout)
        data = b""
        try:
            while True:
                chunk = self.sock.recv(4096)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            pass
        self.sock.settimeout(None)
        self.buffer += data
        result = self.buffer.decode()
        self.buffer = b""
        return result
    
    def send(self, msg):
        self.sock.sendall((msg + "\n").encode())
    
    def parse_encrypted_flag(self, data):
        """Extract encrypted flag values from server output"""
        lines = data.strip().split('\n')
        encrypted = []
        for line in lines:
            line = line.strip()
            if line and line.isdigit():
                encrypted.append(int(line))
            elif line.startswith('  ') and line.strip().lstrip('-').isdigit():
                encrypted.append(int(line.strip()))
        return encrypted
    
    def solve(self):
        # Receive initial welcome and encrypted flag
        print("[*] Connecting and receiving encrypted flag...")
        initial_data = self.recv_all_available(timeout=2)
        print(initial_data[:500])
        
        # Parse encrypted flag ciphertexts
        lines = initial_data.split('\n')
        encrypted_flag = []
        in_flag_section = False
        for line in lines:
            if "encrypted our secret flag" in line:
                in_flag_section = True
                continue
            if in_flag_section:
                stripped = line.strip()
                if stripped and (stripped.isdigit() or (stripped.startswith('-') and stripped[1:].isdigit())):
                    encrypted_flag.append(int(stripped))
                elif "Now you get to encrypt" in line:
                    break
        
        flag_length = len(encrypted_flag)
        print(f"[*] Flag length: {flag_length}")
        
        if flag_length == 0:
            print("[!] Could not parse encrypted flag")
            return
        
        # N values to use - must be coprime to each other
        # N=128 is already used for the flag
        # We need N values coprime to 128 (which is 2^7)
        # So we need odd numbers in range [128, 256)
        N_values = [129, 131, 137, 139, 149, 151, 157]  # Odd primes or odd numbers coprime to each other
        
        # Filter to ensure all are coprime
        final_N = [128]  # Flag was encrypted with N=128
        for n in N_values:
            if all(gcd(n, existing) == 1 for existing in final_N):
                final_N.append(n)
        
        print(f"[*] Using N values: {final_N}")
        
        # For each character, we need to collect residues mod each N
        # residues[i] = {N: char_i mod N}
        residues = [{} for _ in range(flag_length)]
        
        # First, we need to decrypt with N=128 to get flag mod 128
        # But we can't directly decrypt the flag ciphertexts...
        # We need to use the oracle!
        
        # Strategy: 
        # 1. Start new encryption with N (coprime to 128)
        # 2. Encrypt zeros (so adding doesn't change value)
        # 3. Can't add to flag directly... 
        
        # Wait, let me re-read... The flag is encrypted separately and shown to us.
        # We encrypt our own messages and can add/decrypt those.
        # 
        # Ahh! The key insight is that N affects only the decryption!
        # c = pq + Nr + m
        # decrypt: (c mod p) mod N
        # 
        # If we encrypt m=0 and add to some ciphertext:
        # c_new = c + c_0 = pq + Nr + m + pq' + Nr' + 0 = p(q+q') + N(r+r') + m
        # Decrypt: (c_new mod p) mod N = (Nr'' + m) mod N = m mod N (assuming r'' small)
        
        # But we can't add our encryptions to the FLAG ciphertexts - those are just shown to us
        # We need a different approach...
        
        # Actually, we CAN recover the flag characters!
        # Since: c_flag = p*q + 128*r + m (where m is the flag char)
        # And: c_flag mod p = 128*r + m
        # And: (c_flag mod p) mod 128 = m mod 128
        
        # If |128*r + m| < p, then c_flag mod p = 128*r + m exactly
        # rmax = 2^128 / 128 / 4 = 2^128 / 512 = 2^119
        # So 128*r can be up to 128 * 2^119 = 2^126
        # But p is a 128-bit prime, so p ~ 2^127
        # This means 128*r + m < p is likely!
        
        # So the oracle WILL give us m mod 128 correctly, but ASCII is 0-127, so that's the char!
        # For printable ASCII (32-126), m mod 128 = m directly!
        
        # Hmm but we can't decrypt the flag ciphertexts...
        # OR CAN WE?
        
        # Let's try: "new" with same N=128, encrypt message matching flag length
        # Then we have our own ciphertext... but that doesn't help decrypt the flag
        
        # The REAL attack: we need to use the homomorphic property differently
        # 
        # What if we could SUBTRACT the known encrypted chars?
        # If we encrypt our guess for char i: c_guess = p*q' + 128*r' + guess
        # Then c_flag - c_guess decrypts to (m - guess) mod 128
        # If it's 0, our guess is correct!
        
        # But we can only ADD, not subtract... 
        # We can add -guess mod 128 = 128 - guess!
        # 
        # Wait, we can only encrypt chars < N, so max is 127
        # We can encrypt (128 - guess) mod 128, but that requires encoding byte values 1-127
        
        # Actually simpler: for each position, try encrypting 128-guess and adding
        # If decrypt gives 0 (or wraps around properly), we found the char!
        
        # Let's implement the brute force approach with the oracle
        
        flag = []
        for pos in range(flag_length):
            print(f"\n[*] Cracking character {pos+1}/{flag_length}...")
            
            # For printable ASCII (32-126), we'll brute force
            found_char = None
            
            for guess in range(32, 127):
                # Start new encryption with N=128
                self.send("1")  # New encryption
                resp = self.recv_all_available(timeout=0.5)
                
                self.send("128")  # N = 128
                resp = self.recv_all_available(timeout=0.5)
                
                # Encrypt 128 - guess for the target position, 0s elsewhere
                # When added to flag ciphertext: (flag_char + (128-guess)) mod 128
                # If flag_char == guess: result = 0
                
                # But we can't add to the flag... hmm
                
                # Let me reconsider...
                break
            
            # Actually, let me try a different approach
            # Just query the oracle with different N values!
            break
        
        # REVISED APPROACH:
        # The attack is much simpler!
        # 
        # The flag ciphertexts c_i are SHOWN to us as large integers
        # c_i = p*q + 128*r + flag_char_i
        # 
        # If we could recover (c_i mod p), we'd have 128*r + m
        # With r bounded, we could extract m
        # 
        # Key observation: Let's look at the SIZE of c_i
        # c_i ≈ p * q where q is 1024 bits
        # So c_i is about 128 + 1024 = 1152 bits
        # 
        # Given multiple c_i values encrypted with the SAME p:
        # gcd(c_1, c_2) might give us p or a multiple!
        # 
        # But c_i = p*q_i + noise, so gcd won't directly give p...
        # 
        # However! c_1 = p*q_1 + n_1 and c_2 = p*q_2 + n_2
        # c_1*q_2 - c_2*q_1 = n_1*q_2 - n_2*q_1 (small-ish)
        # 
        # This is getting complex. Let me try the simpler approach:
        # We have the encrypted flag values. Let's analyze them!
        
        print("\n[*] Analyzing encrypted flag values...")
        print(f"First few encrypted values: {encrypted_flag[:3]}")
        
        # Try to find GCD between pairs
        # If c = pq + Nr + m, then for two ciphertexts with same p:
        # gcd might reveal something about p
        
        # Actually, the classic DGHV attack uses lattice reduction
        # But let's first verify what oracle access we have...
        
        self.sock.close()
        
        # Actually, I need to reconsider the FULL interaction model
        print("\n[!] Need to reconsider attack strategy...")
        return encrypted_flag


def solve_with_lattice():
    """
    Use lattice reduction to recover p from multiple ciphertexts
    c_i = p * q_i + 128 * r_i + m_i
    
    If we know m_i (e.g., if we can encrypt known plaintexts),
    we can set up a lattice to find p.
    """
    pass


def interactive_solve():
    """Interactive solver to understand the oracle better"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    sock.settimeout(2)
    
    # Receive everything initially
    data = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    
    initial = data.decode()
    print("=== INITIAL DATA ===")
    print(initial)
    print("=== END INITIAL ===\n")
    
    # Parse encrypted flag
    lines = initial.split('\n')
    encrypted_flag = []
    in_flag = False
    for line in lines:
        if "encrypted our secret flag" in line:
            in_flag = True
            continue
        if in_flag:
            stripped = line.strip()
            if stripped and not stripped.startswith("Now"):
                try:
                    val = int(stripped)
                    encrypted_flag.append(val)
                except:
                    pass
            if "Now you get to" in line:
                break
    
    print(f"[*] Parsed {len(encrypted_flag)} encrypted flag characters")
    
    # Now let's understand the oracle
    # Option 1: New encryption - we choose N and encrypt a string
    # Option 2: Add - add new encryption to current ciphertext  
    # Option 3: Decrypt - decrypt current ciphertext
    
    sock.settimeout(None)
    
    # Let's encrypt a known string and see what happens
    print("\n[*] Testing encryption/decryption...")
    
    # Select option 1: New encryption
    sock.sendall(b"1\n")
    data = recv_all(sock)
    print(f"After option 1: {data}")
    
    # Choose N = 128
    sock.sendall(b"128\n")
    data = recv_all(sock)
    print(f"After N=128: {data}")
    
    # Encrypt "A" (0x41 = 65)
    sock.sendall(b"41\n")
    data = recv_all(sock)
    print(f"After encrypting 'A': {data}")
    
    # Decrypt
    sock.sendall(b"3\n")
    data = recv_all(sock)
    print(f"Decrypt result: {data}")
    # Should show "41" (hex for 65, the ASCII code of 'A')
    
    sock.close()
    return encrypted_flag


def recv_all(sock, timeout=1):
    sock.settimeout(timeout)
    data = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    sock.settimeout(None)
    return data.decode()


def main_attack():
    """
    REAL ATTACK:
    
    The key insight is that we can encrypt known bytes and decrypt them!
    This gives us: decrypt(encrypt(m, N)) = m mod N
    
    But we want to decrypt the FLAG ciphertexts, not our own.
    
    Wait... reading more carefully:
    - The server encrypts FLAG with N=128 and SHOWS us the ciphertexts
    - We can encrypt/add/decrypt OUR OWN ciphertexts
    - We CANNOT decrypt the FLAG ciphertexts directly
    
    So the attack must be to RECOVER p from the FLAG ciphertexts!
    
    c = p*q + N*r + m
    
    Given many c_i with the same p, we can use approximate GCD!
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    sock.settimeout(3)
    
    data = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    
    initial = data.decode()
    sock.close()
    
    # Parse ciphertexts
    lines = initial.split('\n')
    encrypted = []
    in_flag = False
    for line in lines:
        if "encrypted our secret flag" in line:
            in_flag = True
            continue
        if in_flag:
            stripped = line.strip()
            if stripped and not stripped.startswith("Now"):
                try:
                    val = int(stripped)
                    encrypted.append(val)
                except:
                    pass
            if "Now you get to" in line or "do you want" in line.lower():
                break
    
    print(f"[*] Got {len(encrypted)} ciphertexts")
    if len(encrypted) < 2:
        print("[!] Not enough ciphertexts")
        return
    
    # Approximate GCD attack
    # c_i = p * q_i + noise_i (where noise = N*r + m is small compared to p*q)
    # 
    # For DGHV, the standard attack uses lattice reduction
    # But a simpler heuristic: 
    # gcd(c_1, c_2) might give us a multiple of p if both q_i share factors
    
    from math import gcd
    
    # Try pairwise GCDs
    print("\n[*] Trying pairwise GCDs...")
    g = encrypted[0]
    for c in encrypted[1:]:
        g = gcd(g, c)
    print(f"GCD of all ciphertexts: {g}")
    print(f"Bit length: {g.bit_length()}")
    
    # That probably gives 1 since q_i are random
    # Let's try approximate GCD using the Simultaneous Diophantine Approximation
    
    # Actually, the noise is very small relative to p*q
    # noise = 128*r + m where r < 2^119 and m < 128
    # So noise < 2^127
    # p is 128 bits, q is 1024 bits, so p*q is ~1152 bits
    # Ratio noise/c ≈ 2^127 / 2^1152 ≈ 2^(-1025)
    
    # This means: c_i ≈ p * q_i with very small error
    # We can use lattice reduction!
    
    print("\n[*] Using lattice attack to recover p...")
    
    # Create lattice matrix for approximate GCD
    # Reference: Howgrave-Graham's approximate GCD algorithm
    n = min(len(encrypted), 5)  # Use first 5 ciphertexts
    ciphertexts = encrypted[:n]
    
    # Run Sage script for lattice attack
    print("[*] Need to use SageMath for lattice reduction...")
    print("[*] Ciphertexts for lattice attack:")
    for i, c in enumerate(ciphertexts):
        print(f"c[{i}] = {c}")
    
    return encrypted


if __name__ == "__main__":
    print("=" * 60)
    print("DGHV Homomorphic Encryption Challenge Solver")
    print("=" * 60)
    
    encrypted = main_attack()
    
    print("\n[*] Saving ciphertexts for SageMath analysis...")
    with open("dghv_ciphertexts.txt", "w") as f:
        for c in encrypted:
            f.write(f"{c}\n")
    print("[*] Saved to dghv_ciphertexts.txt")
