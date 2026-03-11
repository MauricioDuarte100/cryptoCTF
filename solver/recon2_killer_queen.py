"""Interactive recon: try receiving lines and understanding protocol."""
from pwn import *
import time

context.log_level = 'debug'

r = remote("20.244.7.184", 7331)

# Just receive everything for 8 seconds
time.sleep(1)
try:
    data = r.recv(timeout=8)
    print("RAW RECV:", repr(data))
except:
    print("No initial data")

# Try sending a number
r.sendline(b"hello")
time.sleep(1)
try:
    data = r.recv(timeout=5)
    print("AFTER hello:", repr(data))
except:
    print("No data after hello")

r.sendline(b"2")
time.sleep(1)
try:
    data = r.recv(timeout=5)
    print("AFTER 2:", repr(data))
except:
    print("No data after 2")

r.sendline(b"3")
time.sleep(1)
try:
    data = r.recv(timeout=5)
    print("AFTER 3:", repr(data))
except:
    print("No data after 3")

r.close()
