import sys
import socket
import re
import time

HOST = 'challenges3.ctf.sd'
PORT = 33642

# secp256k1 Parameters
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
a = 0

def connect():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((HOST, PORT))
        print(f"[+] Connected to {HOST}:{PORT}")
        return s
    except Exception as e:
        print(f"[-] Connection failed: {e}")
        return None

def recv_until(s, markers):
    buf = ""
    while True:
        try:
            data = s.recv(4096).decode(errors='ignore')
            if not data: break
            buf += data
            for m in markers:
                if m in buf: return buf
        except socket.timeout:
            break
    return buf

def parse_point(s):
    # Regex to capture negative or positive integers
    m = re.search(r'Point\((-?\d+),\s*(-?\d+)\)', s)
    if m:
        return int(m.group(1)), int(m.group(2))
    return None

def attack():
    s = connect()
    if not s: return

    # Wait for banner
    recv_until(s, ["Input C1 >"])
    
    test_points = [
        (0, 1), # b=1
        (0, 2), # b=4
        (0, 3), # b=9
        (1, 2), # b=3
        (1, 3), # b=8
        (1, 4), # b=15
        (2, 1), # b=-7
        (2, 3), # b=1 (Likely redundant with (0,1)? No, different point)
        (2, 5), # b=17
        (3, 5), # b=-2
    ]
    
    results = []
    print("[*] Collecting Data...")
    
    for i, (Px, Py) in enumerate(test_points):
        b_calc = (Py**2 - (Px**3 + a*Px)) % p
        print(f"\nQ{i+1}: P=({Px}, {Py}) -> b={b_calc}")
        
        msg = f"Point({Px}, {Py})"
        
        try:
            s.sendall((msg + "\n").encode())
            recv_until(s, ["Input C2 >"])
            s.sendall((msg + "\n").encode())
            
            res = recv_until(s, ["Query", "Error", "Format", "Input C1 >"])
            
            if "Point(" in res:
                S_pt = parse_point(res)
                if S_pt:
                    Sx, Sy = S_pt
                    print(f"    S = ({Sx}, {Sy})")
                    results.append({'b': b_calc, 'Px': Px, 'Py': Py, 'Sx': Sx, 'Sy': Sy})
                else:
                    print(f"    [-] Parse Failed: {res.strip()}")
            else:
                print(f"    [-] Rejected: {res.strip()[:50]}")
        except Exception as e:
            print(f"    [-] Error: {e}")
            break
            
    s.close()
    
    # Generate Sage Script
    # NOTE: We construct the script to be fully self-contained
    sage_script = f"""
from sage.all import *

# secp256k1
p = {p}
a = {a}
results = {results}

remainders = []
moduli = []

print(f"[*] Analyzing {{len(results)}} items...")

for item in results:
    try:
        b = item['b']
        Px, Py = item['Px'], item['Py']
        Sx, Sy = item['Sx'], item['Sy']
        
        # Define Curve
        E = EllipticCurve(GF(p), [a, b])
        P = E(Px, Py)
        # Handle S normalization if needed (server might return negative representation)
        S = E(Sx, Sy) 
        
        Q = P - S # Q = dP
        
        try:
            order = P.order()
        except:
            print(f"[-] Order calc failed for b={{b}}")
            continue
            
        print(f"[*] b={{b}}, Order={{order}}")
        factors = list(factor(order))
        print(f"    Factors: {{factors}}")
        
        largest_prime = factors[-1][0]
        if largest_prime > 10**16:
            print("    [-] Not smooth.")
            continue
            
        try:
            d_log = discrete_log(Q, P, operation='+')
            print(f"    [+] d = {{d_log}} (mod {{order}})")
            remainders.append(d_log)
            moduli.append(order)
        except Exception as e:
            print(f"    [-] DLP Error: {{e}}")
            
    except Exception as e:
        print(f"[-] Error: {{e}}")

if moduli:
    try:
        print("[*] Applying CRT...")
        d = crt(remainders, moduli)
        print(f"[+] d = {{d}}")
        print(f"[+] Hex: {{hex(d)}}")
        
        flag_candidate = int(d).to_bytes(256, 'big').lstrip(b'\\0')
        print(f"[+] Flag bytes: {{flag_candidate}}")
        print(f"[+] Flag text: {{flag_candidate.decode(errors='ignore')}}")
    except Exception as e:
        print(f"[-] CRT Error: {{e}}")
else:
    print("[-] No moduli.")
"""
    
    with open('solver/recover_key.sage', 'w') as f:
        f.write(sage_script)
    print("\n[+] Script saved to solver/recover_key.sage")

if __name__ == "__main__":
    attack()
