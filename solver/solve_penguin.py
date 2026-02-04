import socket
import hashlib
import string
import itertools
import numpy as np
import ast
import time
import sys
import math
from hashlib import md5

# Configuration
HOST = "instance.penguin.0ops.sjtu.cn"
PORT = 18595
TOTAL_NUMS = 20000
WINDOW = 5

class SimpleConnection:
    def __init__(self, host, port):
        self.sock = socket.create_connection((host, port))
        self.buf = b""
        
    def recvuntil(self, marker):
        if isinstance(marker, str):
            marker = marker.encode()
        while marker not in self.buf:
            try:
                data = self.sock.recv(4096)
                if not data:
                    break
                self.buf += data
            except Exception:
                break
        
        idx = self.buf.find(marker)
        if idx != -1:
            ret = self.buf[:idx+len(marker)]
            self.buf = self.buf[idx+len(marker):]
            return ret
        return self.buf

    def sendline(self, data):
        if isinstance(data, str):
            data = data.encode()
        self.sock.sendall(data + b"\n")

    def recvall(self, timeout=2):
        self.sock.settimeout(timeout)
        try:
            while True:
                data = self.sock.recv(4096)
                if not data: break
                self.buf += data
        except socket.timeout:
            pass
        return self.buf

    def close(self):
        self.sock.close()

def solve_pow(line):
    # Format: sha256(challenge + ???) starts with 000000
    # or similar. Let's parse robustly.
    # Expected line content: "sha256(XXXXXXXX + ???) starts with"
    
    try:
        prefix_part = line.split("sha256(")[1]
        prefix = prefix_part.split(" +")[0]
        
        # Difficulty might be implicit or in the string
        # "starts with 000000"
        if "starts with" in line:
            target_suffix = line.split("starts with")[1].strip().strip("'")
            difficulty = len(target_suffix)
        else:
            # Code says: print(f"sha256({challenge} + ???) starts with {'0' * difficulty}")
            # Try to grab the 0 string
            pass 
            
        print(f"[*] Solving PoW: sha256({prefix} + ???) -> {target_suffix}")
        
        chars = string.ascii_letters + string.digits
        for length in range(1, 10):
            for s in itertools.product(chars, repeat=length):
                ans = "".join(s)
                h = hashlib.sha256((prefix + ans).encode()).hexdigest()
                if h.startswith(target_suffix):
                    return ans
    except Exception as e:
        print(f"[-] PoW Parsing Error: {e}")
        return None

def get_us_from_seed(seed_str):
    seed_int = int(seed_str, 16)
    rng = np.random.default_rng(seed_int)
    us = rng.random(TOTAL_NUMS)
    return us

def score_vector(v):
    if len(v) < WINDOW:
        return 0
        
    high_score_count = 0
    
    for i in range(WINDOW, len(v)):
        prev_slice = v[i-WINDOW : i]
        seed_input = str(prev_slice)
        seed = md5(seed_input.encode()).hexdigest()
        
        us = get_us_from_seed(seed)
        
        idx = v[i]
        if 0 <= idx < TOTAL_NUMS:
            val = us[idx]
            # Metric: count of vals > 0.99
            # Random count (p=0.01) ~ 1.4.
            # Dependent count ~ 20 (surviving clean streaks).
            if val > 0.99:
                high_score_count += 1
            
    return high_score_count

def main():
    try:
        conn = SimpleConnection(HOST, PORT)
        print(f"[+] Connected to {HOST}:{PORT}")
        
        # 1. PoW
        initial_data = conn.recvuntil("Enter your answer: ").decode()
        print(initial_data)
        
        if "Proof of Work" in initial_data and "sha256(" in initial_data:
            lines = initial_data.split("\n")
            pow_line = [l for l in lines if "sha256(" in l][0]
            ans = solve_pow(pow_line)
            if ans:
                print(f"[+] PoW Solved: {ans}")
                conn.sendline(ans)
            else:
                print("[-] PoW Failed")
                return

        # 2. Game Loop
        resp = conn.recvuntil("play the game").decode()
        if "failed" in resp:
            print("[-] PoW Verification Failed by Server")
            return
            
        print("[*] Game Started")
        
        for round_num in range(200):
            prompt = conn.recvuntil("Please tell me the bit of the vector").decode()
            
            if "Vector:" not in prompt:
                print("[-] Vector not found in prompt")
                break
                
            try:
                vec_str = prompt.split("Vector:")[-1].split("Please")[0].strip()
                v = ast.literal_eval(vec_str)
                
                # Metric: Max PRODUCT of 3 consecutive scores.
                # Threshold 90 minimizes overlap based on simulation (Rand Max 88, Dept 1% 280).
                if not v or len(v) < WINDOW:
                   metric = 0
                else:
                    scores = []
                    for i in range(WINDOW, len(v)):
                        prev_slice = v[i-WINDOW : i]
                        seed = md5(str(prev_slice).encode()).hexdigest()
                        us = get_us_from_seed(seed)
                        idx = v[i]
                        if 0 <= idx < TOTAL_NUMS:
                            u = us[idx]
                            val = -math.log(1 - u + 1e-12)
                            scores.append(val)
                    
                    metric = 0
                    if len(scores) >= 3:
                        for k in range(len(scores) - 2):
                            w_prod = scores[k] * scores[k+1] * scores[k+2]
                            if w_prod > metric:
                                metric = w_prod
                    elif scores:
                        metric = 0 
                
                # Threshold 88.
                # Crossover point. Random Max 88.
                # Dependent Min ~76.
                guess = 0 if metric > 88 else 1
                
                print(f"Round {round_num+1}: ProduMetric={metric:.4f} -> Guess={guess}")
                conn.sendline(str(guess))
                
            except Exception as e:
                print(f"[-] Error parsing vector: {e}")
                break
            
            # Validation (optional, checks if Wrong Answer comes immediately)
            # The server prints "Wrong answer" and exits if wrong.
            # But we are in a loop due to buffering?
            # We assume we are right.
            
        print("[*] Finished 200 rounds. Waiting for flag...")
        flag = conn.recvall(timeout=5).decode()
        print("\n" + "="*20)
        print(flag)
        print("="*20)
        
        conn.close()
        
    except Exception as e:
        print(f"[-] Crash: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
