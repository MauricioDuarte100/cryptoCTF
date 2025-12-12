# DGHV Solver - Using interactive oracle to leak p
# The key insight: we can encrypt known messages and analyze the ciphertexts
# to potentially recover p through modular arithmetic

import socket

def get_session():
    """Get a session with the server, returning encrypted flag and interactive socket"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect(("archive.cryptohack.org", 21970))
    
    # Get initial data with encrypted flag
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
    
    initial = data.decode()
    
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

def send_line(sock, msg):
    sock.sendall((msg.strip() + "\n").encode())

def encrypt_and_get_ciphertext(sock, N, msg_bytes):
    """
    The oracle encrypts our message but we don't directly see the ciphertext!
    We only see decrypted values.
    
    BUT: we can exploit the ADD feature!
    
    If we:
    1. Encrypt msg_a with N
    2. Add encryption of msg_b with N  
    3. Decrypt
    
    Result = (msg_a + msg_b) mod N
    
    No direct info about p...
    
    UNLESS: we cause overflow in the noise!
    
    The noise is: N*r + m where r < 2^119
    If we add many encryptions, the noise accumulates:
    sum_noise = N * sum(r_i) + sum(m_i)
    
    If sum_noise > p, then decryption gives:
    ((p*sum_q + sum_noise) mod p) mod N
    = (sum_noise mod p) mod N
    
    When sum_noise < p: result = sum(m_i) mod N
    When sum_noise >= p: result = (sum_noise - k*p) mod N for some k
    
    The transition happens when sum_noise crosses p!
    
    Since p is 128-bit and noise per encryption is ~2^126,
    after ~4 encryptions, noise could exceed p!
    """
    # Option 1: New encryption
    send_line(sock, "1")
    recv_all(sock, 0.5)
    
    # Choose N
    send_line(sock, str(N))
    recv_all(sock, 0.5)
    
    # Message in hex
    hex_msg = ''.join(f'{b:02x}' for b in msg_bytes)
    send_line(sock, hex_msg)
    recv_all(sock, 0.5)
    
    # Now the ciphertext is stored server-side for this session

def add_encryption(sock, N, msg_bytes):
    """Add another encryption to current ciphertext"""
    # Option 2: Add
    send_line(sock, "2")
    recv_all(sock, 0.5)
    
    # Message in hex
    hex_msg = ''.join(f'{b:02x}' for b in msg_bytes)
    send_line(sock, hex_msg)
    recv_all(sock, 0.5)

def decrypt_current(sock):
    """Decrypt current ciphertext and return result"""
    # Option 3: Decrypt
    send_line(sock, "3")
    resp = recv_all(sock, 1)
    
    if "Decrypted message:" in resp:
        hex_result = resp.split("Decrypted message:")[1].strip().split('\n')[0]
        hex_result = hex_result.replace(' ', '')
        return bytes.fromhex(hex_result)
    return None

def noise_overflow_attack(sock, N=128, trials=50):
    """
    Exploit: By adding many encryptions of 0, we accumulate noise.
    
    sum(c_i) = p * sum(q_i) + N * sum(r_i) + sum(m_i)
    
    For m_i = 0:
    sum(c) = p * Q + N * R where Q = sum(q_i), R = sum(r_i)
    
    Decrypt gives: (N*R mod p) mod N
    
    If N*R < p:  result = 0
    If N*R >= p: result = (N*R - k*p) mod N = (-k*p) mod N
    
    Since N and p are coprime (p is prime, N < p), we can learn info about p mod N!
    
    By varying N and counting when overflow happens, we can reconstruct p.
    """
    results = []
    
    # Start with fresh encryption of zero
    encrypt_and_get_ciphertext(sock, N, bytes([0]))
    
    for i in range(trials):
        # Add another zero
        add_encryption(sock, N, bytes([0]))
        
        # Decrypt
        result = decrypt_current(sock)
        if result:
            results.append((i+2, result[0]))  # (num_additions, decrypt_value)
            print(f"  After {i+2} additions: {result[0]}")
    
    return results

def find_p_with_overflow(sock, N=128, max_adds=100):
    """
    Strategy: Add encryptions until we see non-zero output.
    
    Each addition adds noise ~ N * r where r can be up to 2^119.
    Expected noise per addition: N * 2^119 / 2 = N * 2^118
    
    With N=128 = 2^7:
    Expected noise per add: 2^7 * 2^118 = 2^125
    
    p is 2^127 to 2^128, so after ~4-8 additions, we should see overflow.
    
    The exact point of overflow tells us about p!
    """
    # Start fresh encryption
    encrypt_and_get_ciphertext(sock, N, bytes([0]))
    
    results = []
    for i in range(max_adds):
        # Add zero encryption
        add_encryption(sock, N, bytes([0]))
        
        # Decrypt
        result = decrypt_current(sock)
        if result:
            val = result[0]
            results.append((i+2, val))
            
            if val != 0:
                print(f"[!] First non-zero at {i+2} additions: {val}")
                # This is significant!
                # The cumulative noise just exceeded some multiple of p
                
    return results

def crt_attack(max_adds=20):
    """
    Use multiple N values to get residues of p.
    
    For each N, find when overflow happens and what value we get.
    Then use CRT to reconstruct p.
    """
    # N values that are coprime to each other
    N_values = [128, 129, 131, 137, 139, 149]  # 128 = 2^7, rest are odd/prime
    
    residues = {}
    
    for N in N_values:
        print(f"\n[*] Testing N = {N}")
        sock, flag_cts = get_session()
        
        encrypt_and_get_ciphertext(sock, N, bytes([0]))
        
        last_val = 0
        for i in range(max_adds):
            add_encryption(sock, N, bytes([0]))
            result = decrypt_current(sock)
            if result:
                val = result[0]
                if val != last_val:
                    print(f"  Change at {i+2}: {last_val} -> {val}")
                    # The noise crossed a threshold related to p
                    residues[(N, i+2)] = val
                last_val = val
        
        sock.close()
    
    return residues

print("[*] Starting noise overflow attack")
sock, encrypted_flag = get_session()
print(f"[*] Got {len(encrypted_flag)} flag ciphertexts")

results = find_p_with_overflow(sock, N=128, max_adds=30)
print(f"\n[*] Results: {results}")

sock.close()

# Analyze results
print("\n[*] Testing with multiple N values...")
residues = crt_attack(max_adds=30)
print(f"\n[*] Residue info: {residues}")
