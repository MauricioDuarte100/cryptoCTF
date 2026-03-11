"""Recon: minimal, careful protocol probe."""
from pwn import *

context.log_level = 'info'

r = remote("20.244.7.184", 7331, timeout=15)
print("[+] Connected")

# Try recvline with longer timeout  
try:
    line = r.recvline(timeout=10)
    print("LINE1:", repr(line))
except:
    print("No line received, trying recv...")
    try:
        data = r.recv(4096, timeout=10)
        print("RAW:", repr(data))
    except:
        print("Nothing received at all. Server expects us to speak first?")

# Maybe server expects input first - send a number
r.sendline(b"1234567")
try:
    resp = r.recvuntil(b"\n", timeout=10)
    print("RESP1:", repr(resp))
    # Try to get more
    while True:
        more = r.recvline(timeout=3)
        print("MORE:", repr(more))
except Exception as e:
    print(f"Done receiving: {e}")

r.close()
