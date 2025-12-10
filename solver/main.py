import argparse
import sys
import re
import subprocess
import os
from .core.connection import Connection
from .modules import RSASolver, ClassicalSolver, XORSolver, ECCSolver

def detect_type(content):
    """
    Simple heuristic to detect challenge type.
    """
    content = content.lower()
    if "n =" in content and "e =" in content:
        return "rsa"
    if "xor" in content:
        return "xor"
    if "shift" in content or "caesar" in content:
        return "classical"
    if "curve" in content or "generator" in content or ("g =" in content and "p =" in content):
        return "ecc"
    # Default fallback
    return "unknown"

def parse_and_solve(content):
    """
    Parses content for parameters and triggers solvers.
    """
    print(f"[*] Analyzing content ({len(content)} bytes)...")
    chall_type = detect_type(content)
    print(f"[*] Detected Type: {chall_type.upper()}")
    
    flag = None
    
    if chall_type == "rsa":
        # Extract n, e, c
        n_match = re.search(r'n\s*=\s*(\d+)', content)
        e_match = re.search(r'e\s*=\s*(\d+)', content)
        c_match = re.search(r'c\s*=\s*(\d+)', content)
        
        if n_match and e_match and c_match:
            n = int(n_match.group(1))
            e = int(e_match.group(1))
            c = int(c_match.group(1))
            solver = RSASolver()
            flag = solver.solve(n, e, c)
            
    elif chall_type == "ecc":
        # Extract p, a, b, G, P
        # Assuming format: p = ..., a = ..., b = ..., G = (x,y), P = (x,y)
        try:
            p = int(re.search(r'p\s*=\s*(\d+)', content).group(1))
            a = int(re.search(r'a\s*=\s*(\d+)', content).group(1))
            b = int(re.search(r'b\s*=\s*(\d+)', content).group(1))
            
            # G = (x, y)
            g_match = re.search(r'G\s*=\s*\((\d+),\s*(\d+)\)', content)
            G = (int(g_match.group(1)), int(g_match.group(2)))
            
            # P = (x, y)
            p_match = re.search(r'P\s*=\s*\((\d+),\s*(\d+)\)', content)
            P = (int(p_match.group(1)), int(p_match.group(2)))
            
            solver = ECCSolver()
            flag = solver.solve(p, a, b, G, P)
        except Exception as e:
            print(f"[-] Error parsing ECC parameters: {e}")
    
    elif chall_type == "classical":
        solver = ClassicalSolver()
        flag = solver.solve(content)
        
    elif chall_type == "xor":
        # Extract hex string
        hex_match = re.search(r'([0-9a-fA-F]{20,})', content)
        if hex_match:
            solver = XORSolver()
            flag = solver.solve(hex_match.group(1))
            
    return flag

def main():
    parser = argparse.ArgumentParser(description="Crypto CTF Solver")
    parser.add_argument("file", nargs="?", help="Path to challenge file")
    parser.add_argument("--host", help="Target host")
    parser.add_argument("--port", help="Target port")
    
    args = parser.parse_args()
    
    # 1. Handle Connection
    conn = None
    server_output = ""
    if args.host and args.port:
        conn = Connection(args.host, args.port)
        if conn.connect():
            # Receive initial banner
            data = conn.recv(timeout=2)
            server_output = data.decode(errors='ignore')
            print(f"[Server Output]: {server_output}")
            
            # Try to solve based on server output
            flag = parse_and_solve(server_output)
            if flag:
                print(f"\n[SUCCESS] Flag: {flag}")
                print("[*] Sending flag to server...")
                conn.send(flag)
                response = conn.recv()
                print(f"[Server Response]: {response.decode(errors='ignore')}")
                conn.close()
                return

    # 2. Handle File Analysis
    if args.file:
        try:
            content = ""
            if args.file.endswith(".py"):
                print(f"[*] Executing {args.file} to get output...")
                try:
                    result = subprocess.run([sys.executable, args.file], capture_output=True, text=True, timeout=10)
                    content = result.stdout + result.stderr
                    print(f"[*] Execution Output:\n{content}")
                except Exception as e:
                    print(f"[-] Execution failed: {e}")
                    # Fallback to reading file
                    with open(args.file, "r") as f:
                        content = f.read()
            else:
                with open(args.file, "r") as f:
                    content = f.read()
            
            flag = parse_and_solve(content)
            
            if flag:
                print(f"\n[SUCCESS] Flag: {flag}")
                if conn:
                    print("[*] Sending flag to server...")
                    conn.send(flag)
                    response = conn.recv()
                    print(f"[Server Response]: {response.decode(errors='ignore')}")
            else:
                print("[-] Could not solve automatically.")
                
        except Exception as e:
            print(f"[-] Error processing file: {e}")

    # Interactive mode if connected and no flag found
    if conn and not args.file:
        conn.interactive()
    elif conn:
        conn.close()

if __name__ == "__main__":
    main()
