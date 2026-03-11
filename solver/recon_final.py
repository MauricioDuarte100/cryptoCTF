"""
Final definitive test using pwntools (which worked the first time).
One number at a time, wait for response each time.
"""
from pwn import *
import time

context.log_level = 'debug'

for attempt in range(10):
    try:
        r = remote("20.244.7.184", 7331, timeout=30)
        break
    except:
        print(f"Attempt {attempt+1} failed")
        time.sleep(5)
else:
    print("All attempts failed")
    exit(1)

# Wait for anything
time.sleep(2)

# Send ONE number and wait for ONE response
r.sendline(b"42")
time.sleep(3)
try:
    resp = r.recv(4096, timeout=10)
    print(f"\n*** Response to 42: {repr(resp)} ***")
except:
    print("\n*** No response to 42 ***")

# Send another
r.sendline(b"999999999999999999999")
time.sleep(3)
try:
    resp = r.recv(4096, timeout=10)
    print(f"\n*** Response to large: {repr(resp)} ***")
except:
    print("\n*** No response to large ***")

r.close()
