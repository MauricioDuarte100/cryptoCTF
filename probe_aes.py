import socket
import json
import re

def get_trace(plaintext_hex):
    host = "saturn.picoctf.net"
    port = 64402
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(10)
        s.connect((host, port))
        s.recv(1024) # Skip prompt
        s.sendall(f"{plaintext_hex}\n".encode())
        
        response = b""
        while True:
            try:
                chunk = s.recv(16384)
                if not chunk: break
                response += chunk
                if len(chunk) < 16384 and b"]" in chunk: break
            except socket.timeout:
                break
                
        text = response.decode()
        match = re.search(r"\[(.*?)\]", text)
        if match:
            trace = [int(x) for x in match.group(1).split(",")]
            return trace
        return None

if __name__ == "__main__":
    trace = get_trace("00" * 16)
    if trace:
        print(f"Trace length: {len(trace)}")
        print(f"First 10 values: {trace[:10]}")
    else:
        print("Failed to get trace")
