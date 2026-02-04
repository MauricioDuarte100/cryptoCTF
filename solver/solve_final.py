#!/usr/bin/env python3
"""
Final DGHV Solver - Complete attack
Collect residues + CRT + brute force verification
"""

import socket
import time
import random
from math import gcd
from functools import reduce

HOST = "archive.cryptohack.org"
PORT = 21970


def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    g, x1, y1 = extended_gcd(b % a, a)
    return g, y1 - (b // a) * x1, x1


def chinese_remainder_theorem(residues, moduli):
    M = reduce(lambda a, b: a * b, moduli)
    result = 0
    for r, m in zip(residues, moduli):
        Mi = M // m
        _, inv, _ = extended_gcd(Mi % m, m)
        result += r * Mi * inv
    return result % M


def is_prime(n, k=20):
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


class Session:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(10)
        self.sock.connect((HOST, PORT))
        self.encrypted_flag = self._get_initial()
        # Initial state is "Choose N:". We must complete one encryption to reach the main menu.
        self._navigate_to_menu()
    
    def _get_initial(self):
        # Read until "Choose N: "
        data = b""
        self.sock.settimeout(None) # Use blocking
        try:
            while True:
                chunk = self.sock.recv(1)
                if not chunk: break
                data += chunk
                if data.endswith(b"Choose N: "):
                    break
        except:
            pass
        
        # Extract flag from data
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

    def _navigate_to_menu(self):
        # We are at "Choose N: "
        self.send("128")
        self.recv_until_prompt() # Message: 
        self.send("00")
        self.recv_until_prompt() # Menu >

    
    def recv_until_prompt(self):
        data = b""
        try:
            while True:
                chunk = self.sock.recv(1)
                if not chunk:
                    break
                data += chunk
                if data.endswith(b"> ") or data.endswith(b"N: ") or data.endswith(b": "):
                    break
        except Exception as e:
            pass
        print(f"RX: {data}") # Verbose debug
        return data.decode()
    
    def send(self, msg):
        self.sock.sendall((msg.strip() + "\n").encode())
        time.sleep(0.3)
    
    def find_overflow_residue(self, N, max_adds=40):
        """Find p mod N from first overflow"""
        # New encryption
        self.send("1")
        self.recv_until_prompt()
        self.send(str(N))
        self.recv_until_prompt()
        self.send("00")
        self.recv_until_prompt()
        
        prev_val = 0
        for i in range(max_adds):
            # Add
            self.send("2")
            self.recv_until_prompt()
            self.send("00")
            self.recv_until_prompt()
            
            # Decrypt
            self.send("3")
            resp = self.recv_until_prompt()
            
            if "Decrypted message:" in resp:
                try:
                    hex_part = resp.split("Decrypted message:")[1].strip().split('\n')[0].replace(' ', '')
                    if not hex_part:
                         continue
                    curr_val = int(hex_part, 16)
                    
                    if prev_val == 0 and curr_val != 0:
                        # First overflow: value is (N*R - p) mod N ≈ (-p) mod N
                        return (N - curr_val) % N
                    prev_val = curr_val
                except:
                    pass
        
        return None
    
    def close(self):
        self.sock.close()


def main():
    print("=" * 60)
    print("DGHV Final Solver - CRT + Brute Force")
    print("=" * 60)
    
    print("\n[*] Connecting and collecting residues...")
    sess = Session()
    encrypted_flag = sess.encrypted_flag
    print(f"[*] Got {len(encrypted_flag)} encrypted chars")
    
    # Collect residues
    N_values = [128, 129, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241]
    residues = {}
    
    with open("solver_debug.log", "w") as f:
        # Save ciphertexts first!
        f.write(f"CIPHERTEXTS: {encrypted_flag}\n")
        f.flush()
        
        for N in N_values:
            r = sess.find_overflow_residue(N, max_adds=100)
            if r is not None:
                residues[N] = r
                msg = f"p = {r} (mod {N})"
                print(msg)
                f.write(msg + "\n")
            else:
                print(f"Failed to find overflow for N={N}")

    
    sess.close()
    
    print(f"\n[*] Collected {len(residues)} residues")
    
    if len(residues) < 2:
        print("[!] Not enough residues")
        return
    
    # Apply CRT
    N_list = list(residues.keys())
    r_list = [residues[N] for N in N_list]
    
    M = reduce(lambda a, b: a * b, N_list)
    p_mod_M = chinese_remainder_theorem(r_list, N_list)
    
    print(f"\n[*] p ≡ {p_mod_M} (mod M)")
    print(f"[*] M = {M}")
    print(f"[*] log2(M) ≈ {M.bit_length()}")
    
    # Search for p
    k_min = (2**127 - p_mod_M) // M
    k_max = (2**128 - p_mod_M) // M
    
    print(f"\n[*] k range: [{k_min}, {k_max}]")
    print(f"[*] Range size: {k_max - k_min}")
    
    # Known prefix
    known_chars = [
        (0, 99),   # c
        (1, 114),  # r
        (2, 121),  # y
        (3, 112),  # p
        (4, 116),  # t
        (5, 111),  # o
        (6, 123),  # {
        (-1, 125), # }
    ]
    
    noise_bound = 2**127
    
    print("\n[*] Searching for valid p...")
    
    # Try random sampling
    found = False
    tested = 0
    
    for attempt in range(100000):
        k = random.randint(k_min, k_max)
        p = p_mod_M + k * M
        
        if not is_prime(p):
            continue
        
        tested += 1
        
        # Verify against known chars
        valid = True
        for pos, char in known_chars:
            idx = pos if pos >= 0 else len(encrypted_flag) + pos
            noise = (encrypted_flag[idx] - char) % p
            if noise > noise_bound or noise % 128 != 0:
                valid = False
                break
        
        if valid:
            print(f"\n[!!!] Found p after {tested} primes tested!")
            print(f"[*] p = {p}")
            print(f"[*] p has {p.bit_length()} bits")
            
            # Decrypt flag
            flag = ""
            for c in encrypted_flag:
                m = (c % p) % 128
                flag += chr(m)
            
            print(f"\n[!!!] FLAG: {flag}")
            found = True
            break
    
    if not found:
        print(f"\n[*] Tested {tested} primes, no valid p found")
        print("[*] May need more residues or different approach")


if __name__ == "__main__":
    main()
