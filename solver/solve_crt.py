#!/usr/bin/env python3
"""
DGHV Complete Solver - Using noise overflow and CRT to recover p

The attack works as follows:
1. Encrypt zeros repeatedly with the ADD feature
2. Each addition adds noise ~ N * r_i where r_i is random
3. Cumulative noise grows: R_k = r_1 + r_2 + ... + r_k
4. Decrypt gives: (N * R_k mod p) mod N
5. When N * R_k < p: result = 0
6. When N * R_k >= p: result = (N * R_k - p) mod N = (-p) mod N (first overflow)

The key insight: at the FIRST overflow, we get approximately -p mod N!

By using multiple coprime N values and applying CRT, we can recover p.
"""

import socket
import time
from math import gcd
from functools import reduce


def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    g, x1, y1 = extended_gcd(b % a, a)
    return g, y1 - (b // a) * x1, x1


def chinese_remainder_theorem(residues, moduli):
    """Solve x ≡ r_i (mod m_i)"""
    M = reduce(lambda a, b: a * b, moduli)
    result = 0
    for r, m in zip(residues, moduli):
        Mi = M // m
        _, inv, _ = extended_gcd(Mi, m)
        result += r * Mi * inv
    return result % M


class OracleClient:
    def __init__(self, host="archive.cryptohack.org", port=21970):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(10)
        self.sock.connect((host, port))
        self.encrypted_flag = self._get_initial_data()
    
    def _get_initial_data(self):
        data = b""
        self.sock.settimeout(3)
        try:
            while True:
                chunk = self.sock.recv(8192)
                if not chunk:
                    break
                data += chunk
        except socket.timeout:
            pass
        self.sock.settimeout(None)
        
        lines = data.decode().split('\n')
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
                        encrypted.append(int(stripped))
                    except:
                        pass
                if "Now you get to" in line:
                    break
        return encrypted
    
    def recv_all(self, timeout=1):
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
        return data.decode()
    
    def send(self, msg):
        self.sock.sendall((msg.strip() + "\n").encode())
        time.sleep(0.05)
    
    def new_encryption(self, N, msg_bytes):
        self.send("1")
        self.recv_all(0.5)
        self.send(str(N))
        self.recv_all(0.5)
        self.send(msg_bytes.hex())
        self.recv_all(0.5)
    
    def add_encryption(self, msg_bytes):
        self.send("2")
        self.recv_all(0.5)
        self.send(msg_bytes.hex())
        self.recv_all(0.5)
    
    def decrypt(self):
        self.send("3")
        resp = self.recv_all(1)
        if "Decrypted message:" in resp:
            hex_part = resp.split("Decrypted message:")[1].strip().split('\n')[0]
            hex_part = hex_part.replace(' ', '')
            return bytes.fromhex(hex_part)
        return None
    
    def close(self):
        self.sock.close()


def find_first_overflow(host, port, N, max_adds=100):
    """
    Find the decrypt value at first overflow (when we go from 0 to non-zero)
    Returns (num_adds, overflow_value) or None
    """
    client = OracleClient(host, port)
    enc_flag = client.encrypted_flag
    
    client.new_encryption(N, bytes([0]))
    
    prev_val = 0
    for i in range(max_adds):
        client.add_encryption(bytes([0]))
        result = client.decrypt()
        
        if result:
            curr_val = result[0]
            if prev_val == 0 and curr_val != 0:
                client.close()
                return (i + 2, curr_val, enc_flag)
            prev_val = curr_val
    
    client.close()
    return None


def collect_residues(host, port, N_list, max_adds=100):
    """
    Collect (-p mod N) values for multiple N values
    """
    residues = {}
    encrypted_flag = None
    
    for N in N_list:
        print(f"[*] Testing N = {N}...")
        result = find_first_overflow(host, port, N, max_adds)
        
        if result:
            num_adds, overflow_val, enc_flag = result
            print(f"  First overflow at {num_adds} adds: value = {overflow_val}")
            
            # At first overflow: decrypt ≈ (-p mod N)
            # Actually it's (N*R - p) mod N where R is cumulative noise
            # If N*R was just slightly > p, then (N*R - p) is small
            # But if N*R >> p, we might have crossed multiple p thresholds
            
            # The value we see is: (N*R mod p) mod N
            # At first overflow: N*R is just larger than p
            # So N*R mod p ≈ N*R - p
            # And (N*R - p) mod N
            # 
            # Since N*R mod N = 0:
            # (N*R - p) mod N = (-p) mod N = N - (p mod N)
            
            # So: overflow_val = N - (p mod N)
            # => p mod N = N - overflow_val = (N - overflow_val) mod N
            
            p_mod_N = (N - overflow_val) % N
            residues[N] = p_mod_N
            print(f"  => p ≡ {p_mod_N} (mod {N})")
            
            if encrypted_flag is None:
                encrypted_flag = enc_flag
        else:
            print(f"  No overflow detected")
    
    return residues, encrypted_flag


def recover_p(residues):
    """
    Use CRT to recover p from residues
    """
    # Filter for coprime moduli
    N_list = list(residues.keys())
    
    # Find coprime subset
    coprime_N = [N_list[0]]
    for N in N_list[1:]:
        if all(gcd(N, m) == 1 for m in coprime_N):
            coprime_N.append(N)
    
    print(f"\n[*] Using coprime N values: {coprime_N}")
    
    r_list = [residues[N] for N in coprime_N]
    
    # CRT gives us p mod (product of N values)
    M = reduce(lambda a, b: a * b, coprime_N)
    p_candidate = chinese_remainder_theorem(r_list, coprime_N)
    
    print(f"[*] CRT result: p ≡ {p_candidate} (mod {M})")
    
    # p is 128-bit prime, so we need to find the correct one
    # p = p_candidate + k * M for some k
    
    # M is probably small (~10-20 bits if using 5-6 N values)
    # We need to search for k such that p_candidate + k*M is a 128-bit prime
    
    candidates = []
    
    # p is in range [2^127, 2^128)
    k_min = (2**127 - p_candidate) // M
    k_max = (2**128 - p_candidate) // M
    
    print(f"[*] Searching k in range [{k_min}, {k_max}]")
    print(f"[*] This is {k_max - k_min} candidates to check")
    
    # This is too many to brute force...
    # We need more N values or a smarter approach
    
    return p_candidate, M


def is_prime(n, k=20):
    """Miller-Rabin primality test"""
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
    import random
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def decrypt_flag(p, ciphertexts, N=128):
    """Decrypt the flag using p"""
    flag = ""
    for c in ciphertexts:
        m = (c % p) % N
        if 0 <= m < 128:
            flag += chr(m)
        else:
            flag += "?"
    return flag


def main():
    host = "archive.cryptohack.org"
    port = 21970
    
    print("=" * 60)
    print("DGHV Complete Solver - CRT Attack via Noise Overflow")
    print("=" * 60)
    
    # Use multiple coprime N values
    # N must be in [128, 255]
    # We want them coprime to each other for CRT to work
    N_values = [128, 129, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181]
    
    # Collect residues
    print("\n[*] Collecting p mod N residues via overflow attack...")
    residues, encrypted_flag = collect_residues(host, port, N_values[:8], max_adds=80)
    
    if not residues:
        print("[!] Failed to collect residues")
        return
    
    print(f"\n[*] Collected residues for {len(residues)} N values")
    for N, r in residues.items():
        print(f"  p ≡ {r} (mod {N})")
    
    # Try to recover p
    p_mod_M, M = recover_p(residues)
    
    # Since M is small, we can't directly find p
    # But we can verify candidates using the encrypted flag
    
    # Alternative: if we know part of the flag, we can verify
    # Known: flag starts with "crypto{" and ends with "}"
    
    print("\n[*] Trying to verify using known flag format...")
    
    # For each potential p = p_mod_M + k*M, check if decryption makes sense
    # First character 'c' = 99, so:
    # (c[0] % p) % 128 = 99
    
    c0 = encrypted_flag[0]
    
    # (c0 mod p) mod 128 = 99
    # c0 mod p = 99 + 128*j for some j >= 0
    # Since c0 mod p < p and p < 2^128, j can be large
    
    # c0 = p*q + 128*r + 99
    # c0 - 99 = p*q + 128*r
    # (c0 - 99) mod p = 128*r (small, < 2^126)
    
    # So if we guess p correctly:
    # (c0 - 99) mod p should be small (< 2^126)
    
    print(f"[*] c[0] - 99 = {c0 - 99}")
    print(f"[*] bit length: {(c0-99).bit_length()}")
    
    # Use the residue to narrow down
    # p ≡ p_mod_M (mod M)
    # c0 - 99 = p*q + small
    # (c0 - 99) mod p = small
    
    # (c0 - 99) ≡ 0 (mod gcd(c0-99, p)) if p divides part of c0-99
    # This doesn't directly help...
    
    print("\n[*] The CRT gives us partial info but M is too small")
    print("[*] Need lattice-based attack to fully recover p")
    
    # Save data for lattice attack
    with open("residues.txt", "w") as f:
        for N, r in residues.items():
            f.write(f"{N} {r}\n")
    
    print("\n[*] Saved residues to residues.txt")
    print("[*] Saved encrypted flag to flag_ciphertexts.txt (from previous run)")


if __name__ == "__main__":
    main()
