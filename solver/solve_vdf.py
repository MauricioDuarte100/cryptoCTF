"""
Solver for VDF Proof Challenge
tcp.flagyard.com:31850

Strategy:
1. Server asserts h % n == (pi^l * g^r) % n
2. Server gives us 'proof' such that: result % n == (proof^l * g^r) % n
   (using the SAME l and r derived from our h)
3. If we set h = -result (mod n), i.e., h = n - result
4. Then we need pi^l * g^r = -result
5. Since proof^l * g^r = result, we have:
   pi^l * g^r = - (proof^l * g^r) = (-proof^l) * g^r
   pi^l = -proof^l
6. If l is odd, -proof^l = (-proof)^l
   So pi = -proof (mod n) = n - proof
7. l is a 40-bit random prime, so l is odd with prob ~1.

This satisfies all conditions (h != result, pi != proof).
"""

from pwn import *

HOST = "tcp.flagyard.com"
PORT = 31850

print(f"🔌 Connecting to {HOST}:{PORT}...")
io = remote(HOST, PORT)

# Get modulus
io.recvuntil(b"modulus is ")
n = int(io.recvline().strip())
print(f"📊 n = {n}")

# Get result
io.recvuntil(b"g^(2^(2^256)) == ")
result = int(io.recvline().strip())
print(f"📊 result = {result}")

# Calculate h = -result mod n
h = n - result
print(f"🎯 Sending h = {h}")
io.sendline(str(h).encode())

# Get l and proof
io.recvuntil(b"my challenge is ")
l = int(io.recvline().strip())
print(f"📊 l = {l}")

if l == 2:
    print("❌ Critical failure: l=2 (even). This strategy requires odd l.")
    exit(1)

io.recvuntil(b"the correct proof is ")
proof = int(io.recvline().strip())
print(f"📊 proof = {proof}")

# Calculate pi = -proof mod n
pi = n - proof
print(f"🎯 Sending pi = {pi}")
io.sendline(str(pi).encode())

# Get flag
response = io.recvall(timeout=5)
print(f"\nScroll down for flag:\n{response.decode()}")

io.close()
