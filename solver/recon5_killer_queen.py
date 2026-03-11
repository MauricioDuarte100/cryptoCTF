"""Test if the server actually transforms input via Chebyshev polynomial."""
from pwn import *
import time

context.log_level = 'info'

r = remote("20.244.7.184", 7331, timeout=20)
print("[+] Connected")
time.sleep(0.5)

# Send large numbers as test
test_values = [
    "100",
    "999",
    "123456789",
    "1000000007",
    "99999999999999997",
]

for val in test_values:
    r.sendline(val.encode())
    time.sleep(1)

# Wait and collect all responses
time.sleep(3)
try:
    data = r.recv(8192, timeout=5)
    print("=== RESPONSES ===")
    lines = data.decode(errors='replace').strip().split('\n')
    for i, line in enumerate(lines):
        line = line.strip()
        if line:
            print(f"  Input: {test_values[i] if i < len(test_values) else '?'}")
            print(f"  Output: {line}")
            if i < len(test_values) and line != test_values[i]:
                print(f"  ** TRANSFORMED! **")
            print()
except Exception as e:
    print(f"Error: {e}")

r.close()
