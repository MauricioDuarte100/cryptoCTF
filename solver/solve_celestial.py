#!/usr/bin/env python3
"""
Celestial CTF Solver - Testing message-independent verification

Key insight from ICC2022: if signing uses h = Hint(R+pk+m) but
verification uses h = Hint(R+pk) (without message), then:

1. Get valid signature (R, S) for any message m
2. The signature will verify for ANY message m' 
   (because h doesn't depend on m in verification)

Let me test this directly.
"""

from pwn import *
import hashlib

context.log_level = 'info'

# Ed25519 parameters  
b = 256
q = 2**255 - 19
l = 2**252 + 27742317777372353535851937790883648493

def H(m):
    return hashlib.sha512(m).digest()

def bit(h, i):
    return (h[i // 8] >> (i % 8)) & 1

def Hint(m):
    h = H(m)
    return sum(2**i * bit(h, i) for i in range(2 * b))

def decodeint(s):
    return sum(2**i * bit(s, i) for i in range(0, b))

def encodeint(y):
    bits = [(y >> i) & 1 for i in range(b)]
    return bytes([sum([bits[i * 8 + j] << j for j in range(8)]) for i in range(b // 8)])

def inv_mod(a, m):
    return pow(a, -1, m)

TARGET = b'gimme the flag'


def solve():
    host = "tcp.flagyard.com"
    port = 13509
    
    io = remote(host, port)
    
    io.recvuntil(b"pk (hex): ")
    pk_hex = io.recvline().strip().decode()
    pk = bytes.fromhex(pk_hex)
    log.info(f"pk: {pk_hex}")
    
    # Get a signature on any allowed message
    test_msg = b'hello'
    io.recvuntil(b"command: ")
    io.sendline(b"sign")
    io.recvuntil(b"message (hex): ")
    io.sendline(test_msg.hex().encode())
    sig_hex = io.recvline().strip().decode()
    sig = bytes.fromhex(sig_hex)
    
    log.info(f"Got signature for '{test_msg.decode()}'")
    log.info(f"Signature: {sig_hex}")
    
    # Theory: if verification doesn't check message in h,
    # this same signature should verify for target
    
    log.info("Trying direct signature reuse...")
    io.recvuntil(b"command: ")
    io.sendline(b"verify")
    io.recvuntil(b"signature (hex): ")
    io.sendline(sig_hex.encode())
    
    result = io.recvline().decode()
    log.info(f"Result: {result}")
    
    if "invalid" not in result.lower():
        log.success("SIGNATURE REUSE WORKS!")
        remaining = io.recvall(timeout=5).decode()
        print("\n" + "="*60)
        print(result + remaining)
        print("="*60)
    else:
        log.warning("Signature reuse failed")
        
        # Theory 2: Maybe if we compute the correct S for target message 
        # using the same R but adjusted S
        
        # If both signing and verification use h = Hint(R+pk+m):
        # S_sign = r + h_sign * a  where h_sign = Hint(R+pk+test_msg)
        # We need S_verify = r + h_verify * a where h_verify = Hint(R+pk+TARGET)
        
        # S_verify - S_sign = (h_verify - h_sign) * a
        # S_verify = S_sign + (h_verify - h_sign) * a
        
        # Problem: we don't know 'a'
        
        # BUT: if we get TWO signatures with SAME R (nonce reuse)
        # we can recover 'a' and then forge
        
        log.info("Need to check if same message gives same R (deterministic nonce)...")
        
        # Sign same message again
        io.recvuntil(b"command: ")
        io.sendline(b"sign")
        io.recvuntil(b"message (hex): ")
        io.sendline(test_msg.hex().encode())
        sig2_hex = io.recvline().strip().decode()
        sig2 = bytes.fromhex(sig2_hex)
        
        R1 = sig[:32]
        R2 = sig2[:32]
        
        if R1 == R2:
            log.info("Same message -> same R (deterministic nonce)")
            # This is expected for proper ed25519
            # We need two DIFFERENT messages to have same R for nonce reuse
        else:
            log.warning("Same message -> different R (random nonce)")
            # This would be a vulnerability!
    
    io.close()


if __name__ == "__main__":
    solve()
