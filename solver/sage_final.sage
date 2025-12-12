# Combine CRT residues with lattice to recover p
# Run in SageMath

import socket

# CRT Residues from overflow attack (IMPORTANT: each session has different p!)
# These are from a specific session, need to get fresh ones each time

def get_session_with_residues():
    """Get encrypted flag AND collect residues in same session"""
    import time
    
    # First, get encrypted flag
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect(("archive.cryptohack.org", 21970))
    
    data = b""
    sock.settimeout(3)
    try:
        while True:
            chunk = sock.recv(8192)
            if not chunk:
                break
            data += chunk
    except:
        pass
    sock.settimeout(None)
    
    # Parse encrypted flag
    lines = data.decode().split('\n')
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
                    encrypted_flag.append(Integer(stripped))
                except:
                    pass
            if "Now you get to" in line:
                break
    
    return sock, encrypted_flag

def recv_all(sock, timeout=1):
    sock.settimeout(timeout)
    data = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    except:
        pass
    sock.settimeout(None)
    return data.decode()

def send(sock, msg):
    sock.sendall((msg.strip() + "\n").encode())
    import time
    time.sleep(0.05)

def find_overflow(sock, N, max_adds=100):
    """Find first overflow value for this N in current session"""
    # New encryption with N
    send(sock, "1")
    recv_all(sock, 0.5)
    send(sock, str(N))
    recv_all(sock, 0.5)
    send(sock, "00")  # encrypt zero
    recv_all(sock, 0.5)
    
    prev_val = 0
    for i in range(max_adds):
        # Add zero
        send(sock, "2")
        recv_all(sock, 0.5)
        send(sock, "00")
        recv_all(sock, 0.5)
        
        # Decrypt
        send(sock, "3")
        resp = recv_all(sock, 1)
        
        if "Decrypted message:" in resp:
            hex_part = resp.split("Decrypted message:")[1].strip().split('\n')[0].replace(' ', '')
            curr_val = int(hex_part, 16)
            
            if prev_val == 0 and curr_val != 0:
                return (N - curr_val) % N  # p mod N
            prev_val = curr_val
    
    return None

print("[*] Getting fresh session and collecting residues...")
sock, encrypted_flag = get_session_with_residues()
print(f"[*] Got {len(encrypted_flag)} encrypted flag characters")

# Collect residues for multiple N values
N_values = [128, 129, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197]
residues = {}

for N in N_values:
    r = find_overflow(sock, N, max_adds=80)
    if r is not None:
        residues[N] = r
        print(f"  p ≡ {r} (mod {N})")

sock.close()

print(f"\n[*] Collected {len(residues)} residues")

# Use CRT to get p mod M
N_list = list(residues.keys())
r_list = [residues[N] for N in N_list]

# Compute p mod M using CRT
M = prod(N_list)
p_mod_M = CRT(r_list, N_list)

print(f"[*] p ≡ {p_mod_M} (mod {M})")
print(f"[*] M has {M.nbits()} bits")

# Now use lattice to find exact p
# p = p_mod_M + k * M for some k
# We know p is 128 bits

# From encrypted flag:
# c_0 = p*q_0 + 128*r_0 + 99 (first char is 'c')
# c_0 - 99 = p*q_0 + 128*r_0
#
# For correct p: (c_0 - 99) mod p = 128*r_0 < 2^126

c0 = encrypted_flag[0]
c0_adj = c0 - 99  # Adjusted for known first char 'c'

print(f"\n[*] c[0] - 99 = {c0_adj}")
print(f"[*] c[0] - 99 has {c0_adj.nbits()} bits")

# Build lattice to find k such that:
# p = p_mod_M + k * M is a 128-bit prime
# AND (c0_adj) mod p < 2^126

# We can formulate this as:
# c0_adj = p * q + e where e < 2^126
# c0_adj = (p_mod_M + k*M) * q + e
# c0_adj - p_mod_M * q = k*M*q + e
#
# Define: a = c0_adj, b = p_mod_M, W = M
# a = (b + k*W) * q + e
# a - b*q = k*W*q + e = k*W*q + e
#
# We want small k*q (since k ~ 2^127/M ~ 2^(127-55) ~ 2^72)

# Alternative: use the structure directly
# c0_adj ≡ 128*r_0 (mod p)
# c0_adj ≡ 128*r_0 (mod p_mod_M + k*M)
#
# For small r_0 (< 2^119): 128*r_0 < 2^126
# So c0_adj mod p = 128*r_0 exactly when p > 128*r_0

# Let's try: enumerate k values and check if p is prime AND makes sense
# k range: p in [2^127, 2^128)
# p = p_mod_M + k*M
# 2^127 <= p_mod_M + k*M < 2^128
# (2^127 - p_mod_M) / M <= k < (2^128 - p_mod_M) / M

k_min = (2^127 - p_mod_M) // M
k_max = (2^128 - p_mod_M) // M

print(f"\n[*] k range: [{k_min}, {k_max}]")
print(f"[*] Search space: {k_max - k_min} candidates")

if k_max - k_min > 10^12:
    print("[!] Search space too large for brute force")
    print("[*] Need additional constraints...")
    
    # Use multiple ciphertexts for additional constraints
    # For prefix "crypto{": m = [99, 114, 121, 112, 116, 111, 123]
    known_prefix = [99, 114, 121, 112, 116, 111, 123]
    
    # For each i: c[i] - m[i] = p * q_i + 128 * r_i
    # So (c[i] - m[i]) mod p < 2^126
    
    # If we try a candidate p:
    # Check if EVERY (c[i] - m[i]) mod p is small
    
    # The probability of a random p passing one check is 2^126 / p ~ 1/4
    # With 7 checks: (1/4)^7 = 1/16384
    # So random p is very unlikely to pass all checks
    
    # We can sample k uniformly and test
    import random
    
    print("\n[*] Random sampling k values...")
    
    tested = 0
    for _ in range(10000):
        k = random.randint(int(k_min), int(k_max))
        p = p_mod_M + k * M
        
        if not is_prime(p):
            continue
        
        tested += 1
        
        # Verify all known prefix positions
        valid = True
        for i, m in enumerate(known_prefix):
            noise = (encrypted_flag[i] - m) % p
            if noise > 2^127:  # Noise bound
                valid = False
                break
        
        if valid:
            print(f"\n[!!!] Found valid p = {p}")
            print(f"[*] p has {p.nbits()} bits")
            
            # Decrypt flag
            flag = ""
            for c in encrypted_flag:
                char_val = (c % p) % 128
                flag += chr(char_val)
            
            print(f"\n[!!!] FLAG: {flag}")
            break
    
    print(f"\n[*] Tested {tested} primes")

else:
    print("[*] Enumerating all k values...")
    
    known_prefix = [99, 114, 121, 112, 116, 111, 123]
    
    for k in range(int(k_min), int(k_max) + 1):
        p = p_mod_M + k * M
        
        if not is_prime(p):
            continue
        
        # Quick check: first char
        if (encrypted_flag[0] - 99) % p > 2^127:
            continue
        
        # Full prefix check
        valid = True
        for i, m in enumerate(known_prefix):
            noise = (encrypted_flag[i] - m) % p
            if noise > 2^127:
                valid = False
                break
        
        if valid:
            print(f"\n[!!!] Found p = {p}")
            
            flag = ""
            for c in encrypted_flag:
                char_val = (c % p) % 128
                flag += chr(char_val)
            
            print(f"[!!!] FLAG: {flag}")
            break

print("\n[*] Done!")
