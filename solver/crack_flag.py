import hashlib
from Crypto.Cipher import AES
import sys

def get_keys(msg_str):
    return hashlib.sha256(msg_str.encode()).digest()[:16]

def decrypt(key, enc_flag_hex):
    ct_bytes = bytes.fromhex(enc_flag_hex)
    nonce = ct_bytes[:8]
    ciphertext = ct_bytes[8:]
    cipher = AES.new(key=key, mode=AES.MODE_CTR, nonce=nonce)
    try:
        pt = cipher.decrypt(ciphertext)
        return pt
    except:
        return b""

def main():
    print("Loading m...")
    with open("recovered_m.txt", "r") as f:
        m = eval(f.read()) # list
        
    print("Loading enc_flag...")
    with open(r'c:\Users\Nenaah\Desktop\Programacion\GIT\cryptoCTF\challenges\broadcasting-ntru\broadcasting-ntru\output.txt', 'r') as f:
        data = f.read()
    enc_flag = data.split("encrypted flag:")[1].strip()
    
    print("Brute forcing formats...")
    
    candidates = []
    candidates.append(("Normal", m))
    candidates.append(("Reversed", m[::-1]))
    candidates.append(("Inverted", [1-x for x in m]))
    candidates.append(("Inverted Reversed", [1-x for x in m][::-1]))
    
    if len(m) == 509:
        # Cyclic shifts?
        pass # Too many
        
    print(f"Adding {len(m)} single-bit flip candidates...")
    base_m = list(m)
    for i in range(len(m)):
        m_flip = list(base_m)
        m_flip[i] = 1 - m_flip[i]
        candidates.append((f"Flip {i}", m_flip))
        

        
    for name, bits in candidates:
        # Generate string formats
        # 1. Decreasing x^... + ...
        # Standard Sage with spaces
        terms = []
        for i in range(len(bits)-1, -1, -1):
            if bits[i] == 1:
                if i == 0: terms.append("1")
                elif i == 1: terms.append("x")
                else: terms.append(f"x^{i}")
        
        s1 = " + ".join(terms)
        s2 = "+".join(terms)
        s3 = " + ".join(terms).replace("x", "1*x") # unlikely
        s4 = s1.replace("x", "x^1")
        s5 = s1.replace(" ", "")
        
        string_formats = [s1, s2, s3, s4, s5]
        
        # Increasing order
        terms_inc = terms[::-1]
        s_inc1 = " + ".join(terms_inc)
        s_inc2 = "+".join(terms_inc)
        
        string_formats.append(s_inc1)
        string_formats.append(s_inc2)
        
        for s in string_formats:
            key = get_keys(s)
            
            # Try offsets
            for offset in [0, 4, 8, 12, 16]:
                if offset >= len(enc_flag)//2: continue
                # Enc flag is hex.
                # ct_bytes total len.
                # If offset is 8 bytes.
                # We need to reconstruction ciphertext and nonce.
                # Assume nonce is prefix of size offset?
                # If offset=0, nonce=""? AES CTR requires nonce (or nonce=b"").
                
                # We assume cipher.nonce + enc_flag in challenge means 
                # Total Bytes = Nonce || Ciphertext
                # If Nonce is N bytes.
                # Decrypt(Ct) using Nonce.
                
                try:
                    ct_bytes_full = bytes.fromhex(enc_flag)
                    current_nonce = ct_bytes_full[:offset]
                    current_ct = ct_bytes_full[offset:]
                    
                    if not current_ct: continue
                    
                    cipher = AES.new(key=key, mode=AES.MODE_CTR, nonce=current_nonce)
                    pt = cipher.decrypt(current_ct)
                    
                    if pt.startswith(b"CTF") or pt.startswith(b"flag") or pt.startswith(b"FLAG"):
                         print(f"FOUND PREFIX! Mode: {name} Offset: {offset} Flag: {pt}")
                         return
                         
                    try:
                        dec = pt.decode()
                        printable = sum(1 for c in dec if 32 <= ord(c) <= 126)
                        if printable > 0.8 * len(dec) and len(dec) > 5:
                            print(f"POSSIBLE ASCII (Mode {name} Off {offset}): {pt}")
                    except:
                        pass
                except:
                    pass

    print("Finished checking.")

if __name__ == "__main__":
    main()
