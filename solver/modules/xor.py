class XORSolver:
    """
    Solver for XOR challenges.
    """
    def solve(self, data):
        """
        Attempts to solve XOR challenges.
        Accepts bytes or hex string.
        """
        print("[*] Attempting XOR solve...")
        
        if isinstance(data, str):
            try:
                # Try interpreting as hex
                data = bytes.fromhex(data)
            except:
                # Interpret as raw bytes
                data = data.encode()
        
        # Single Byte XOR
        for key in range(256):
            decrypted = bytes([b ^ key for b in data])
            try:
                res = decrypted.decode()
                if "flag{" in res.lower() or "ctf{" in res.lower():
                    print(f"[+] Solved with Single Byte XOR key {key}: {res}")
                    return res
            except:
                pass
                
        return None
