#!/usr/bin/env python3
"""
DGHV Challenge Solver - Oracle-Based Attack

Re-analyzing the challenge:

1. The FLAG is encrypted with N=128 and shown to us (just the ciphertext values)
2. We have an ORACLE that lets us:
   - Start new encryption with ANY N in [128, 255]
   - Encrypt our chosen message bytes
   - ADD more encryptions to current ciphertext
   - DECRYPT current ciphertext

KEY INSIGHT:
The decrypt oracle returns (c mod p) mod N

If we encrypt byte X with modulus N, decrypt gives X mod N = X (since X < N)
But the FLAG bytes were encrypted with N=128.

ATTACK IDEA:
If we could somehow "re-encrypt" the flag ciphertext with a different N,
the decryption would give flag_byte mod N_new.

But wait... we can't modify the FLAG ciphertexts!

BETTER ATTACK:
The homomorphic property: encrypt(a) + encrypt(b) decrypts to (a + b) mod N

What if we:
1. Encrypt zeros with N=128 to get our own ciphertext c_our = p*q + 128*r + 0
2. Can we somehow add the FLAG ciphertext to ours?
   
NO - the FLAG ciphertexts are just SHOWN to us, not stored server-side for operations.

ALTERNATIVE - CHARACTER BY CHARACTER BRUTE FORCE:
We know FLAG characters are printable ASCII (32-126).
For each position, we can:
1. Start new encryption with N=128
2. Encrypt test byte X
3. Decrypt - get X back
4. This confirms the oracle works, but doesn't help with FLAG...

WAIT - THE REAL ATTACK:

Looking at the code more carefully:
- We control N (128-255)
- We control what we encrypt
- We can ADD and then DECRYPT

The FLAG ciphertexts are: c_flag_i = p*q_i + 128*r_i + flag_byte_i

For ASCII, flag_byte_i is in [32, 126] typically.

We can't operate on FLAG ciphertexts, but we can OBSERVE them.

THE LATTICE ATTACK IS NECESSARY for recovering p from the FLAG ciphertexts alone.

BUT... there might be a simpler approach if we have enough ciphertexts.

Let me try a different angle: CHINESE REMAINDER THEOREM with the oracle!

1. Use the oracle with different N values (coprime to 128)
2. Encrypt same known byte, e.g., 100
3. Decrypt with each N to verify system works
4. For the FLAG: we only have ciphertexts encrypted with N=128
5. If we could get the server to DECRYPT the FLAG ciphertexts...

ACTUALLY: The server stores its own p and uses it for our encryptions!
The FLAG was encrypted with the SAME p!

So if we can find p through our interactions, we can decrypt the FLAG!

BINARY SEARCH FOR p:
1. Encrypt some byte m with N close to p
2. The ciphertext c = p*q + N*r + m
3. If we encrypt two different m values and look at the difference...

This still doesn't directly give us p.

FINAL APPROACH - LATTICE OR NOTHING:
The approximage GCD problem requires lattice reduction for these parameters.

Let me try using numpy/scipy for a simpler lattice reduction.
"""

import socket
import numpy as np

HOST = "archive.cryptohack.org"
PORT = 21970


class OracleClient:
    def __init__(self, host, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(5)
        self.sock.connect((host, port))
        self.buffer = b""
        
    def recv_until_prompt(self, timeout=2):
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
    
    def get_encrypted_flag(self):
        """Get the initial encrypted flag"""
        initial = self.recv_until_prompt(3)
        
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
                        encrypted.append(int(stripped))
                    except:
                        pass
                if "Now you get to" in line:
                    break
        
        return encrypted
    
    def encrypt_and_decrypt(self, N, message_bytes):
        """
        Use oracle to encrypt and decrypt a message
        Returns the decrypted bytes
        """
        # Option 1: New encryption
        self.send("1")
        self.recv_until_prompt(1)
        
        # Choose N
        self.send(str(N))
        self.recv_until_prompt(1)
        
        # Message in hex
        hex_msg = message_bytes.hex()
        self.send(hex_msg)
        self.recv_until_prompt(1)
        
        # Option 3: Decrypt
        self.send("3")
        resp = self.recv_until_prompt(1)
        
        # Parse decrypted message
        if "Decrypted message:" in resp:
            hex_result = resp.split("Decrypted message:")[1].strip().split('\n')[0]
            hex_result = hex_result.replace(' ', '')
            return bytes.fromhex(hex_result)
        
        return None
    
    def close(self):
        self.sock.close()


def test_oracle():
    """Test the oracle functionality"""
    print("[*] Testing oracle...")
    
    client = OracleClient(HOST, PORT)
    encrypted_flag = client.get_encrypted_flag()
    print(f"[*] Got {len(encrypted_flag)} flag ciphertexts")
    
    # Test encrypt/decrypt with known message
    test_msg = b"ABC"  # 0x41 0x42 0x43
    result = client.encrypt_and_decrypt(128, test_msg)
    print(f"[*] Encrypted 'ABC', decrypted: {result}")
    
    client.close()
    return encrypted_flag


def lll_reduction_numpy(basis):
    """
    Simple LLL implementation using numpy
    This is a basic version - not as efficient as fpylll/sage
    """
    n = len(basis)
    B = np.array(basis, dtype=np.float64)
    
    def gram_schmidt(B):
        n = len(B)
        B_star = np.zeros_like(B)
        mu = np.zeros((n, n))
        
        for i in range(n):
            B_star[i] = B[i].copy()
            for j in range(i):
                if np.dot(B_star[j], B_star[j]) > 1e-10:
                    mu[i][j] = np.dot(B[i], B_star[j]) / np.dot(B_star[j], B_star[j])
                    B_star[i] = B_star[i] - mu[i][j] * B_star[j]
        
        return B_star, mu
    
    delta = 0.75
    k = 1
    
    while k < n:
        B_star, mu = gram_schmidt(B)
        
        # Size reduction
        for j in range(k-1, -1, -1):
            if abs(mu[k][j]) > 0.5:
                q = round(mu[k][j])
                B[k] = B[k] - q * B[j]
                B_star, mu = gram_schmidt(B)
        
        # Lovász condition
        if np.dot(B_star[k], B_star[k]) >= (delta - mu[k][k-1]**2) * np.dot(B_star[k-1], B_star[k-1]):
            k += 1
        else:
            # Swap
            B[k], B[k-1] = B[k-1].copy(), B[k].copy()
            k = max(k-1, 1)
    
    return B.astype(int).tolist()


def approximate_gcd_lattice(ciphertexts, noise_bits=126):
    """
    Use lattice reduction to solve approximate GCD
    
    Given c_0 = p*q_0 + e_0, c_1 = p*q_1 + e_1, ...
    Construct lattice to find p
    """
    print("\n[*] Attempting lattice-based approximate GCD (numpy implementation)")
    
    n = min(5, len(ciphertexts))
    c0 = ciphertexts[0]
    
    # Construct the lattice matrix
    # We use a simpler formulation for numerical stability
    # 
    # The matrix:
    # [ 2^noise_bits   0         0     ...   0   ]
    # [ c_1           c_0        0     ...   0   ]
    # [ c_2            0        c_0    ...   0   ]
    # ...
    # [ c_{n-1}        0         0     ...  c_0  ]
    
    # This is too large for numpy... the numbers are 1000+ bits
    
    print(f"[*] Ciphertext bit length: {ciphertexts[0].bit_length()}")
    print("[!] Numbers too large for numpy - need proper LLL implementation")
    
    return None


def main():
    print("=" * 60)
    print("DGHV Challenge Solver - Oracle Attack")
    print("=" * 60)
    
    # Test oracle to understand the system
    encrypted_flag = test_oracle()
    
    # The lattice attack requires proper big-integer LLL
    # Let's save the data and provide a Sage script
    
    print("\n[*] Generating SageMath script...")
    
    sage_script = '''#!/usr/bin/env sage
# DGHV Approximate GCD Solver
# Run with: sage solve_agcd.sage

ciphertexts = [
'''
    for c in encrypted_flag:
        sage_script += f"    {c},\n"
    
    sage_script += ''']

print(f"[*] Loaded {len(ciphertexts)} ciphertexts")

# Parameters
noise_bits = 126
N = 128

# Method 1: Howgrave-Graham's Orthogonal Lattice Attack
def orthogonal_lattice_attack(cts, num=5):
    """
    Create orthogonal lattice from approximate GCD instances
    """
    n = min(num, len(cts))
    c0 = cts[0]
    
    # Scale factor
    K = 2^noise_bits
    
    # Build matrix: first row is scaling, rest encode differences
    M = matrix(ZZ, n, n)
    M[0, 0] = K
    for i in range(1, n):
        M[0, i] = cts[i]  
        M[i, i] = -c0
    
    print(f"[*] Running LLL on {n}x{n} matrix...")
    L = M.LLL()
    
    print("[*] Checking short vectors...")
    for row in L:
        for entry in row:
            if entry != 0:
                g = gcd(c0, abs(entry))
                if g > 1 and 120 <= g.nbits() <= 140:
                    print(f"  Candidate: {g} ({g.nbits()} bits)")
                    if is_prime(g):
                        return g
    
    return None

# Method 2: Use ratios
def ratio_attack(cts):
    """
    Use continued fractions on ratios
    """
    c0, c1 = cts[0], cts[1]
    
    cf = continued_fraction(c0/c1)
    for conv in cf.convergents()[:100]:
        h, k = conv.numerator(), conv.denominator()
        if k == 0:
            continue
        
        diff = c0 * k - c1 * h
        if diff != 0:
            g = gcd(c0, abs(diff))
            if g > 1 and 120 <= g.nbits() <= 140 and is_prime(g):
                print(f"[!] Found p via CF: {g}")
                return g
    
    return None

# Method 3: Multivariate approach
def multivariate_attack(cts, dim=7):
    """
    Use more ciphertexts for a better lattice
    """
    n = min(dim, len(cts))
    c0 = cts[0]
    
    # Construct Coppersmith-style lattice
    K = 2^(noise_bits + 10)  # Slightly larger scale
    
    M = matrix(ZZ, n+1, n+1)
    M[0, 0] = K
    for i in range(n):
        M[i+1, 0] = cts[i]
        M[i+1, i+1] = c0
    
    print(f"[*] Running BKZ on {n+1}x{n+1} matrix...")
    L = M.BKZ(block_size=20)
    
    print("[*] Analyzing reduced basis...")
    candidates = []
    for row in L:
        val = row[0]
        if val != 0 and val.nbits() < 200:
            # This might be related to p
            g = gcd(c0, abs(val))
            if 1 < g.nbits() <= 140:
                candidates.append(g)
    
    return candidates

# Run attacks
print("\\n[*] Running ratio attack...")
p = ratio_attack(ciphertexts)

if not p:
    print("\\n[*] Running orthogonal lattice attack...")
    p = orthogonal_lattice_attack(ciphertexts, num=6)

if not p:
    print("\\n[*] Running multivariate attack...")
    candidates = multivariate_attack(ciphertexts)
    for c in set(candidates):
        if is_prime(c) and 120 <= c.nbits() <= 140:
            p = c
            break

if p:
    print(f"\\n[!!!] Found p = {p}")
    print(f"[*] p has {p.nbits()} bits")
    
    # Decrypt flag
    flag = ""
    for c in ciphertexts:
        m = (c % p) % N
        flag += chr(m)
    
    print(f"\\n[!!!] FLAG: {flag}")
else:
    print("\\n[!] Could not find p")
'''
    
    with open("solve_agcd.sage", "w") as f:
        f.write(sage_script)
    
    print("[*] Created solve_agcd.sage")
    print("[*] To solve: install SageMath and run 'sage solve_agcd.sage'")
    
    # Also try online Sage
    print("\n[*] Trying alternative: sympy-based factoring")
    
    # Last resort: try if the ciphertexts share small factors
    from math import gcd
    from functools import reduce
    
    g = reduce(gcd, encrypted_flag)
    print(f"[*] GCD of all ciphertexts: {g}")
    
    # Try factor differences
    diffs = [abs(encrypted_flag[i] - encrypted_flag[j]) 
             for i in range(min(5, len(encrypted_flag))) 
             for j in range(i+1, min(5, len(encrypted_flag)))]
    g_diff = reduce(gcd, diffs)
    print(f"[*] GCD of differences: {g_diff}")


if __name__ == "__main__":
    main()
