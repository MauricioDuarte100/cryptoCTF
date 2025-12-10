import socket
import random
import time
import re
import sys

# Configuration
HOST = 'remote.infoseciitr.in'
PORT = 4006
MOD = 10**9 + 7
N = 896
K = 256

def mod_inv(a, m):
    return pow(a, m - 2, m)

# Optimized Lagrange Interpolation
class LagrangeSolver:
    def __init__(self, X, m):
        self.X = X
        self.m = m
        self.n = len(X)
        self.M = self.compute_master_poly()
        self.weights = self.compute_weights()
        
    def compute_master_poly(self):
        # M(x) = prod(x - x_i)
        # M[k] is coeff of x^k
        # Start with 1
        M = [0] * (self.n + 1)
        M[0] = 1 
        # Actually, let's use the representation where index i is x^i.
        # So M = [1] initially (constant 1).
        # Multiply by (x - x_i) -> x*M - x_i*M
        # If M has degree d, x*M has degree d+1.
        
        # To avoid list resizing, let's allocate full size.
        # But iterating is faster on small lists.
        # Let's just use the loop I had, it was fine.
        M = [1]
        for x_i in self.X:
            new_M = [0] * (len(M) + 1)
            for k in range(len(M)):
                # Term M[k] * x^k
                # Multiply by -x_i: -x_i * M[k] * x^k
                val = (M[k] * -x_i) % self.m
                new_M[k] = (new_M[k] + val) % self.m
                # Multiply by x: M[k] * x^{k+1}
                new_M[k+1] = (new_M[k+1] + M[k]) % self.m
            M = new_M
        return M

    def compute_weights(self):
        # w_j = 1 / prod(x_j - x_i)
        # This is 1 / M'(x_j)
        # Compute derivative of M
        M_prime = []
        for k in range(1, len(self.M)):
            # Term M[k] * x^k -> derivative k * M[k] * x^{k-1}
            M_prime.append((self.M[k] * k) % self.m)
            
        weights = []
        for x_j in self.X:
            # Evaluate M_prime at x_j
            val = 0
            x_pow = 1
            for coeff in M_prime:
                val = (val + coeff * x_pow) % self.m
                x_pow = (x_pow * x_j) % self.m
            weights.append(mod_inv(val, self.m))
        return weights

    def interpolate(self, Y):
        # P(x) = sum y_j * w_j * (M(x) / (x - x_j))
        # Let c_j = y_j * w_j
        # We need sum c_j * Q_j(x) where Q_j(x) = M(x) / (x - x_j)
        
        # Optimization:
        # Q_j(x) coeffs can be computed from M(x) and x_j.
        # Let M(x) = sum m_k x^k
        # Q_j(x) = sum q_{j,k} x^k
        # q_{j, n-1} = m_n
        # q_{j, k-1} = m_k + x_j * q_{j, k}
        
        # We want A_k = sum_j c_j * q_{j, k}
        # A_{n-1} = sum c_j * m_n = m_n * sum(c_j)
        # A_{k-1} = sum c_j * (m_k + x_j * q_{j, k})
        #         = m_k * sum(c_j) + sum(c_j * x_j * q_{j, k})
        
        # Let S_k = sum_j c_j * q_{j, k}  (This is A_k)
        # We need to track T_k = sum_j c_j * q_{j, k} ? No.
        
        # Let's look at the recurrence again.
        # q_{j, k} depends on k.
        # For a fixed k, q_{j, k} is a value for each j.
        # We want sum_j c_j * q_{j, k}.
        
        # Let's iterate k from n-1 down to 0.
        # For k=n-1: q_{j, n-1} = m_n (constant for all j).
        # A_{n-1} = sum_j c_j * m_n = m_n * sum(c_j).
        
        # For k-1:
        # q_{j, k-1} = m_k + x_j * q_{j, k}
        # A_{k-1} = sum_j c_j * (m_k + x_j * q_{j, k})
        #         = m_k * sum(c_j) + sum_j (c_j * x_j * q_{j, k})
        
        # This looks like we need to maintain a state for each j.
        # Let state_j = q_{j, k}. Initially (for k=n), state_j = 0?
        # No, for k=n-1, state_j = m_n.
        # Then for k-2, state_j = m_{n-1} + x_j * state_j (previous).
        
        # So:
        # Initialize state_j = 0 for all j.
        # Iterate k from n down to 1.
        #   Update state_j = m_k + x_j * state_j
        #   (This computes q_{j, k-1})
        #   A_{k-1} = sum_j c_j * state_j
        
        # This allows us to compute A_{k-1} in O(n) if we update all state_j.
        # Updating all state_j takes O(n).
        # Total complexity O(n^2).
        # This avoids the inner loop of synthetic division!
        # It's just simple arithmetic updates.
        
        C = [(Y[j] * self.weights[j]) % self.m for j in range(self.n)]
        
        # State for each j. Initially 0.
        # Actually, q_{j, n-1} = m_n.
        # Let's follow the recurrence carefully.
        # M has indices 0 to n. M[n] is coeff of x^n.
        
        # We want A_0 to A_{n-1}.
        
        # Initialize state[j] = 0.
        # Loop k from n down to 1:
        #   new_state[j] = (M[k] + x_j * state[j])
        #   A_{k-1} = sum(C[j] * new_state[j])
        #   state[j] = new_state[j]
        
        state = [0] * self.n
        A = [0] * self.n
        
        for k in range(self.n, 0, -1):
            m_k = self.M[k]
            current_A = 0
            for j in range(self.n):
                state[j] = (m_k + self.X[j] * state[j]) % self.m
                term = (C[j] * state[j]) % self.m
                current_A = (current_A + term) % self.m
            A[k-1] = current_A
            
        return A

def connect():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10) # 10 second timeout
    s.connect((HOST, PORT))
    return s

def read_until(s, delim):
    buf = b""
    while not buf.endswith(delim):
        try:
            data = s.recv(4096)
            if not data: break
            buf += data
            # print(f"DEBUG: Received {len(data)} bytes")
        except socket.timeout:
            print("[-] Socket timeout")
            break
        except Exception as e:
            print(f"[-] Socket error: {e}")
            break
    return buf.decode()

def solve_challenge():
    while True:
        s = None
        try:
            print("[*] Connecting...")
            s = connect()
            
            # Read initial text
            initial = read_until(s, b"Press Enter to start > ")
            s.sendall(b"\n")
            
            # Read leaked numbers
            leaked_data = read_until(s, b"\n> ")
            match = re.search(r"Here are the leaked numbers : ([\d,]+)", leaked_data)
            if not match:
                print("[-] Could not find leaked numbers")
                s.close()
                continue
                
            numbers = list(map(int, match.group(1).split(',')))
            print(f"[+] Leaked {len(numbers)} numbers")
            
            # Precompute Lagrange Solver
            print("[*] Precomputing Lagrange values...")
            solver = LagrangeSolver(numbers, MOD)
            print("[+] Precomputation done")
            
            # Generate balanced polynomial for first prompt
            print("[*] Generating balanced polynomial for initial check...")
            # We need to distribute 896 numbers into 256 slots (3 or 4 per slot).
            # 128 slots get 4, 128 slots get 3.
            Y_initial = [0] * N
            num_idx = 0
            for slot in range(128):
                for _ in range(4):
                    if num_idx < N:
                        Y_initial[num_idx] = slot
                        num_idx += 1
            for slot in range(128, 256):
                for _ in range(3):
                    if num_idx < N:
                        Y_initial[num_idx] = slot
                        num_idx += 1
            
            initial_coeffs = solver.interpolate(Y_initial)
            initial_coeff_str = ",".join(map(str, initial_coeffs[::-1]))
            s.sendall(initial_coeff_str.encode() + b"\n")
            
            # Read until "Press Enter to continue > "
            read_until(s, b"> ")
            s.sendall(b"\n")
            
            candidates = list(range(K)) # 0 to 255
            
            for trial in range(6):
                print(f"[*] Trial {trial + 1}/6. Candidates: {len(candidates)}")
                
                read_until(s, b"> ")
                
                if len(candidates) <= 1:
                    # We already know the answer, just send dummy
                    s.sendall(b"1\n")
                    read_until(s, b"\n\n")
                    continue
                
                mid = len(candidates) // 2
                target_set = candidates[mid:] 
                safe_set = candidates[:mid]   
                
                S = target_set[:] # Copy
                needed = 128 - len(S)
                non_candidates = [x for x in range(K) if x not in candidates]
                S.extend(non_candidates[:needed])
                
                S_set = set(S)
                Not_S = [x for x in range(K) if x not in S_set]
                
                # Map numbers to slots
                # We need Y values for each X (number)
                # X values are fixed (numbers list)
                # We need Y array corresponding to numbers array
                
                Y_vals = [0] * N
                num_idx = 0
                
                # Fill S (4 each)
                for slot in S:
                    for _ in range(4):
                        if num_idx < N:
                            Y_vals[num_idx] = slot
                            num_idx += 1
                            
                # Fill Not-S (3 each)
                for slot in Not_S:
                    for _ in range(3):
                        if num_idx < N:
                            Y_vals[num_idx] = slot
                            num_idx += 1
                            
                # Interpolate
                coeffs = solver.interpolate(Y_vals)
                
                # Send coefficients (Reversed because server expects highest degree first)
                coeff_str = ",".join(map(str, coeffs[::-1]))
                s.sendall(coeff_str.encode() + b"\n")
                
                # Read result
                result = read_until(s, b"\n\n")
                
                if "failed" in result:
                    print("[-] Failed -> Target in Upper Half")
                    candidates = target_set 
                else:
                    print("[+] Passed -> Target in Lower Half")
                    candidates = safe_set
            
            # End of trials
            print(f"[*] Candidates left: {candidates}")
            guess = random.choice(candidates)
            print(f"[*] Guessing: {guess}")
            
            read_until(s, b"Tell your friend the index : ")
            s.sendall(f"{guess}\n".encode())
            
            final_res = read_until(s, b"\n")
            if "saved" in final_res:
                print("[+] SUCCESS!")
                # Read flag
                flag_data = read_until(s, b"}")
                print(flag_data)
                break
            else:
                print("[-] Failed guess. Retrying...")
                s.close()
                
        except Exception as e:
            print(f"[-] Error: {e}")
            if s: s.close()
            time.sleep(1)

if __name__ == "__main__":
    solve_challenge()
