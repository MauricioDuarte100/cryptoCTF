#!/usr/bin/env python3
"""
DGHV Noise Overflow Attack

Key insight: When we add multiple encryptions together, noise accumulates.
c_1 + c_2 + ... + c_k = p*sum(q_i) + N*sum(r_i) + sum(m_i)

If we add encryptions of zero:
sum(c_i) = p*Q + N*R where Q = sum(q_i), R = sum(r_i)

Decrypt gives: (N*R mod p) mod N

When N*R < p:  result = 0
When N*R >= p: result = (N*R mod p) mod N != 0 (usually)

By detecting when we first get non-zero, we learn when N*R crossed p!
This gives us information about p.
"""

import socket
import time


def get_session(host="archive.cryptohack.org", port=21970):
    """Connect and get encrypted flag"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect((host, port))
    
    # Get initial data
    data = b""
    sock.settimeout(3)
    try:
        while True:
            chunk = sock.recv(8192)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
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
                    encrypted_flag.append(int(stripped))
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
    except socket.timeout:
        pass
    sock.settimeout(None)
    return data.decode()


def send_line(sock, msg):
    sock.sendall((msg.strip() + "\n").encode())
    time.sleep(0.1)


def new_encryption(sock, N, msg_bytes):
    """Start new encryption with N and message"""
    send_line(sock, "1")
    recv_all(sock, 0.5)
    
    send_line(sock, str(N))
    recv_all(sock, 0.5)
    
    hex_msg = msg_bytes.hex()
    send_line(sock, hex_msg)
    recv_all(sock, 0.5)


def add_encryption(sock, msg_bytes):
    """Add encryption to current ciphertext"""
    send_line(sock, "2")
    recv_all(sock, 0.5)
    
    hex_msg = msg_bytes.hex()
    send_line(sock, hex_msg)
    recv_all(sock, 0.5)


def decrypt_current(sock):
    """Decrypt and return result bytes"""
    send_line(sock, "3")
    resp = recv_all(sock, 1)
    
    if "Decrypted message:" in resp:
        hex_part = resp.split("Decrypted message:")[1].strip().split('\n')[0]
        hex_part = hex_part.replace(' ', '')
        return bytes.fromhex(hex_part)
    return None


def test_overflow(host, port, N=128, max_adds=50):
    """
    Test: Add multiple zero encryptions and detect overflow
    """
    print(f"\n[*] Testing noise overflow with N={N}")
    
    sock, encrypted_flag = get_session(host, port)
    print(f"[*] Got {len(encrypted_flag)} flag ciphertexts")
    
    # Start with encryption of zero
    new_encryption(sock, N, bytes([0]))
    
    results = []
    for i in range(max_adds):
        add_encryption(sock, bytes([0]))
        result = decrypt_current(sock)
        
        if result:
            val = result[0]
            results.append((i + 2, val))  # +2 because we started with one encryption
            print(f"  After {i+2} adds: decrypt = {val}")
            
            # Check if we got non-zero (overflow detected!)
            if val != 0:
                print(f"\n[!] OVERFLOW at {i+2} additions! Value = {val}")
    
    sock.close()
    return results, encrypted_flag


def binary_search_overflow(host, port, N=128):
    """
    Use binary search to find exact overflow point
    """
    print(f"\n[*] Binary search for overflow point with N={N}")
    
    # First, find upper bound where overflow definitely happens
    upper = 100
    lower = 1
    
    sock, _ = get_session(host, port)
    new_encryption(sock, N, bytes([0]))
    
    for i in range(upper):
        add_encryption(sock, bytes([0]))
        result = decrypt_current(sock)
        if result and result[0] != 0:
            upper = i + 2
            break
    
    sock.close()
    
    print(f"[*] Found overflow within {upper} additions")
    
    # Now binary search (but each test needs new connection)
    # This is slow but precise
    
    return upper


def multi_n_attack(host, port, max_adds=40):
    """
    Test with multiple N values to gather more info about p
    """
    # N must be in [128, 255] per the server assertion
    N_values = [128, 129, 131, 137, 139, 149, 151, 157]
    
    all_results = {}
    
    for N in N_values:
        print(f"\n{'='*40}")
        print(f"[*] Testing N = {N}")
        
        try:
            sock, enc_flag = get_session(host, port)
            new_encryption(sock, N, bytes([0]))
            
            results = []
            for i in range(max_adds):
                add_encryption(sock, bytes([0]))
                result = decrypt_current(sock)
                
                if result:
                    val = result[0]
                    results.append(val)
                    
                    if val != 0 and len(results) >= 2 and results[-2] == 0:
                        print(f"  First overflow at {i+2} adds: {val}")
            
            all_results[N] = results
            sock.close()
            
        except Exception as e:
            print(f"  Error: {e}")
    
    return all_results


def main():
    host = "archive.cryptohack.org"
    port = 21970
    
    print("=" * 60)
    print("DGHV Noise Overflow Attack")
    print("=" * 60)
    
    # Test basic overflow
    results, encrypted_flag = test_overflow(host, port, N=128, max_adds=30)
    
    # Save encrypted flag for later
    with open("flag_ciphertexts.txt", "w") as f:
        for c in encrypted_flag:
            f.write(f"{c}\n")
    
    print("\n[*] Saved flag ciphertexts to flag_ciphertexts.txt")
    
    # If we see overflow, try to exploit it
    non_zero = [(n, v) for n, v in results if v != 0]
    if non_zero:
        print(f"\n[!] Detected {len(non_zero)} overflow events!")
        print(f"[!] First overflow: {non_zero[0]}")
        
        # The number of additions tells us roughly how big p is
        # Each addition adds noise ~ N * r where r ~ 2^118 on average
        # cumulative noise ~ k * 128 * 2^118 = k * 2^125
        # Overflow when cumulative > p
        # So k * 2^125 > p means p < k * 2^125
        
        k = non_zero[0][0]
        print(f"[*] Estimated p < {k} * 2^125 = 2^{125 + k.bit_length()}")
    
    # Try multi-N attack
    # print("\n[*] Running multi-N attack...")
    # multi_results = multi_n_attack(host, port, max_adds=25)


if __name__ == "__main__":
    main()
