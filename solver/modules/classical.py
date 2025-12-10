class ClassicalSolver:
    """
    Solver for classical ciphers like Caesar.
    """
    def solve(self, text):
        """
        Attempts to solve classical ciphers.
        """
        print("[*] Attempting Classical solve...")
        
        # Caesar Cipher
        for shift in range(1, 26):
            decrypted = ""
            for char in text:
                if char.isalpha():
                    ascii_offset = 65 if char.isupper() else 97
                    decrypted += chr((ord(char) - ascii_offset - shift) % 26 + ascii_offset)
                else:
                    decrypted += char
            
            if "flag{" in decrypted.lower() or "ctf{" in decrypted.lower():
                print(f"[+] Solved with Caesar shift {shift}: {decrypted}")
                return decrypted
                
        return None
