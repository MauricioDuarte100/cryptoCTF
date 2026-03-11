"""Recon script: connect to Killer Queen and observe the initial banner/protocol."""
from pwn import *

r = remote("20.244.7.184", 7331)

# Receive everything available in the first few seconds
data = r.recvrepeat(timeout=5)
print("=== INITIAL BANNER ===")
print(data.decode(errors='replace'))

# Try sending a simple input to see what happens
r.sendline(b"1")
data2 = r.recvrepeat(timeout=5)
print("=== AFTER SENDING '1' ===")
print(data2.decode(errors='replace'))

# Try another input
r.sendline(b"1")
data3 = r.recvrepeat(timeout=5)
print("=== AFTER SECOND SEND ===")
print(data3.decode(errors='replace'))

# Try a few more
for i in range(3):
    r.sendline(str(i+2).encode())
    d = r.recvrepeat(timeout=3)
    print(f"=== ROUND {i+3} ===")
    print(d.decode(errors='replace'))

r.close()
