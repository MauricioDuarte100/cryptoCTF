import socket
import sys
import re
import random
import time
from math import gcd

# Configuration
HOST = 'challenges3.ctf.sd'
PORT = 33642

def inverse(a, n):
    t, newt = 0, 1
    r, newr = n, a
    while newr != 0:
        quotient = r // newr
        t, newt = newt, t - quotient * newt
        r, newr = newr, r - quotient * newr
    if r > 1:
        return None
    if t < 0:
        t = t + n
    return t

class ZwiqueSolver:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = None
        self.N = None
        self.V = None # Public key (v = s^2 mod N)
        self.buffer = ""

    def connect(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(5)
            self.sock.connect((self.host, self.port))
            print(f"[+] Connected to {self.host}:{self.port}")
            return True
        except Exception as e:
            print(f"[-] Connection failed: {e}")
            return False

    def receive_until(self, markers):
        if isinstance(markers, str):
            markers = [markers]
        while True:
            for marker in markers:
                if marker in self.buffer:
                    return marker
            try:
                chunk = self.sock.recv(4096).decode(errors='ignore')
                if not chunk:
                    raise ConnectionError("Connection closed")
                self.buffer += chunk
                print(chunk, end='')
            except socket.timeout:
                return None

    def send_line(self, line):
        print(f"{line}")
        self.sock.sendall((line + "\n").encode())
        time.sleep(0.1)

    def parse_params(self):
        # Look for N = ... and V = ... or similar
        # This is a heateruistic parse based on common CTF formats
        try:
            # Matches N = 123... or N: 123...
            n_match = re.search(r'[Nn]\s*[:=]\s*(\d+)', self.buffer)
            v_match = re.search(r'[Vv]\s*[:=]\s*(\d+)', self.buffer)
            
            if n_match: self.N = int(n_match.group(1))
            if v_match: self.V = int(v_match.group(1))
            
            if self.N:
                print(f"[+] Found N: {self.N}")
            if self.V:
                print(f"[+] Found V: {self.V}")
                
        except Exception as e:
            print(f"[!] Error parsing params: {e}")

    def solve(self):
        if not self.connect():
            return

        try:
            # 1. Initial Handshake & Parameter Extraction
            print("[*] Waiting for challenge banner...")
            self.receive_until(['>', ':', 'demonstration'])
            self.parse_params()
            
            # 2. Information Gathering (Passive/Active)
            # We assume the server does a "demonstration" where IT is the prover.
            # We need to act as Verifier to collect nonces, or just observe.
            
            history = {} # x -> {challenge_bit: response_y}
            secret_s = None
            
            rounds_to_observe = 20
            print(f"[*] Observing {rounds_to_observe} rounds for nonce reuse...")
            
            for i in range(rounds_to_observe):
                # 2.1 Wait for commitment X
                # Server usually says: "x = 1234..." or just sends it
                self.receive_until(['x =', 'x:', 'Commitment:'])
                x_match = re.search(r'[xX]\s*[:=]\s*(\d+)', self.buffer)
                if not x_match:
                    print("[!] Could not find commitment X")
                    # Try to trigger it?
                    self.send_line("") 
                    continue
                    
                x = int(x_match.group(1))
                self.buffer = "" # Clear buffer
                
                # 2.2 Send Challenge (0 or 1)
                # We alternate or try to get both for same X if possible.
                # If we are the verifier, WE choose the bit.
                # To exploit nonce reuse, we hope the server reuses x for different sessions OR
                # allows us to query multiple times? 
                # Actually, if it's one connection, x usually changes. 
                # BUT if PRNG is weak, x might repeat.
                # Let's try sending random bit.
                
                c = random.randint(0, 1)
                self.send_line(str(c))
                
                # 2.3 Receive Response Y
                self.receive_until(['y =', 'y:', 'Response:'])
                y_match = re.search(r'[yY]\s*[:=]\s*(\d+)', self.buffer)
                if not y_match:
                    print("[!] Could not find response Y")
                    continue
                    
                y = int(y_match.group(1))
                self.buffer = ""
                
                print(f"    Round {i}: x={x[:20]}..., c={c}, y={y[:20]}...")
                
                # Store and check collision
                if x not in history:
                    history[x] = {}
                
                history[x][c] = y
                
                # Check if we have both c=0 and c=1 for this x
                if 0 in history[x] and 1 in history[x]:
                    y0 = history[x][0] # y0 = r
                    y1 = history[x][1] # y1 = r * s
                    
                    # s = y1 * inv(y0)
                    y0_inv = inverse(y0, self.N)
                    if y0_inv:
                        secret_s = (y1 * y0_inv) % self.N
                        print(f"\n[+] NONCE REUSE DETECTED!")
                        print(f"[+] Recovered Secret s: {secret_s}")
                        break
            
            if not secret_s:
                print("\n[-] Failed to recover secret (no nonce reuse observed yet).")
                print("[-] Ensure you are interacting correctly or increase rounds.")
                return

            # 3. Impersonation Phase
            # Now we authenticate AS Zwique using s
            print("\n[*] Initiating identification proof...")
            # Look for an option to "Prove" or "Login"
            self.send_line("prove") # Hypothetical command
            
            # Server asks for commitment x
            # We generate r, x = r^2 mod N
            r = random.randint(2, self.N - 1)
            x_us = pow(r, 2, self.N)
            self.send_line(str(x_us))
            
            # Server sends challenge c
            self.receive_until(['c =', 'c:', 'Challenge:'])
            c_match = re.search(r'[cC]\s*[:=]\s*(\d+)', self.buffer)
            if c_match:
                c_server = int(c_match.group(1))
                # Response y = r * s^c
                y_us = (r * pow(secret_s, c_server, self.N)) % self.N
                self.send_line(str(y_us))
                
                # 4. Get Flag
                res = self.receive_until(['flag', '}'])
                print(f"\n[+] Result: {res}")
            
        except KeyboardInterrupt:
            print("\n[*] Interrupted")
        except Exception as e:
            print(f"\n[!] Error: {e}")
        finally:
            if self.sock: self.sock.close()

if __name__ == "__main__":
    solver = ZwiqueSolver(HOST, PORT)
    solver.solve()
