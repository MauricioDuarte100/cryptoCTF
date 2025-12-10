from pwn import *
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import hashlib
import sys

# context.log_level = 'debug'

def get_shared_secret_point(private_key_bytes, peer_public_key_bytes):
    try:
        # Load Private Key
        if len(private_key_bytes) == 32:
            priv_val = int.from_bytes(private_key_bytes, 'big')
            priv_key = ec.derive_private_key(priv_val, ec.SECP256R1())
        elif len(private_key_bytes) < 32:
             # Small scalar
             priv_val = int.from_bytes(private_key_bytes, 'big')
             priv_key = ec.derive_private_key(priv_val, ec.SECP256R1())
        else:
            return None

        # Load Public Key
        if len(peer_public_key_bytes) == 65 and peer_public_key_bytes[0] == 4:
             pub_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), peer_public_key_bytes)
        elif len(peer_public_key_bytes) == 33:
             pub_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), peer_public_key_bytes)
        elif len(peer_public_key_bytes) == 64:
             pub_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b'\x04' + peer_public_key_bytes)
        else:
             return None

        # Perform ECDH
        shared_key = priv_key.exchange(ec.ECDH(), pub_key)
        return shared_key
    except Exception as e:
        return None

def solve():
    r = remote('remote.infoseciitr.in', 4007)
    
    log.info("Receiving data...")
    # Skip the huge key dump
    r.recvuntil(b"[+] Computing shared secret")
    
    # Read Encrypted Data
    r.recvuntil(b"[Nonce: ")
    nonce_hex = r.recvuntil(b"]", drop=True).decode()
    nonce = bytes.fromhex(nonce_hex)
    
    r.recvuntil(b"[Ciphertext: ")
    ct_hex = r.recvuntil(b"]", drop=True).decode()
    ciphertext = bytes.fromhex(ct_hex)
    
    log.info(f"Nonce: {nonce_hex}")
    log.info(f"Ciphertext: {ct_hex}")
    
    # Try static keys (ignoring ECDH)
    log.info("Testing static keys (bypassing ECDH)...")
    static_words = [b"bread", b"BREAD", b"Bread", b"bread_conv", b"prisoner", b"keys"]
    for w in static_words:
        keys_to_try = []
        keys_to_try.append(hashlib.sha256(w).digest())
        keys_to_try.append(hashlib.md5(w).digest().ljust(32, b'\x00'))
        keys_to_try.append(w.ljust(32, b'\x00'))
        
        for k, key in enumerate(keys_to_try):
             # Try GCM
            try:
                aesgcm = AESGCM(key)
                pt = aesgcm.decrypt(nonce, ciphertext, None)
                if b"flag" in pt.lower() or b"ctf" in pt.lower() or b"Infosec" in pt:
                    log.success(f"FOUND FLAG with static key '{w}' variant {k}")
                    log.success(f"Flag: {pt}")
                    return
            except: pass
            
            # Try ChaCha
            try:
                chacha = ChaCha20Poly1305(key)
                pt = chacha.decrypt(nonce, ciphertext, None)
                if b"flag" in pt.lower() or b"ctf" in pt.lower() or b"Infosec" in pt:
                    log.success(f"FOUND FLAG with static key '{w}' variant {k}")
                    log.success(f"Flag: {pt}")
                    return
            except: pass

    log.failure("Static keys failed.")

    # Load candidate public keys
    candidate_pub_keys = []
    try:
        # Read the raw blob from key_debug.txt
        with open("key_debug.txt", "r") as f:
            lines = f.readlines()
            hex_data = ""
            for line in lines:
                if line.startswith("Hex: "):
                    hex_data = line.strip().split(" ")[1]
                    break
        
        if hex_data:
            blob_bytes = bytes.fromhex(hex_data)
            # Try first 32 bytes as compressed key
            if len(blob_bytes) >= 32:
                chunk = blob_bytes[:32]
                candidate_pub_keys.append(b'\x02' + chunk)
                candidate_pub_keys.append(b'\x03' + chunk)
                log.info(f"Added first 32 bytes of blob as candidates: {chunk.hex()}")
            
            # Try hash of blob as static key
            blob_hash = hashlib.sha256(blob_bytes).digest()
            static_words.append(blob_hash) # Will be hashed again in loop, but that's fine
            # Also add raw blob hash to keys_to_try manually in the loop
            
    except Exception as e:
        log.error(f"Failed to read key_debug.txt: {e}")

    try:
        with open("candidates.txt", "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    candidate_pub_keys.append(bytes.fromhex(line))
        log.info(f"Loaded {len(candidate_pub_keys)} candidate public keys.")
    except FileNotFoundError:
        log.warning("candidates.txt not found. Only using blob start.")

    # Candidate Private Keys
    priv_candidates = []
    # "bread" variants
    words = [b"bread", b"BREAD", b"Bread", b"bread\n", b"keys", b"prisoner", b"bread_conv"]
    for w in words:
        priv_candidates.append(w.ljust(32, b'\x00'))
        priv_candidates.append((w * 10)[:32])
        priv_candidates.append(hashlib.sha256(w).digest())
        priv_candidates.append(hashlib.md5(w).digest().ljust(32, b'\x00'))
        priv_candidates.append(w) # Small scalar
        
    log.info(f"Testing {len(priv_candidates)} private key candidates against {len(candidate_pub_keys)} public keys.")
    log.info("Starting brute-force...")
    
    for i, pub_bytes in enumerate(candidate_pub_keys):
        if i % 100 == 0:
            print(f"Checking public key {i}/{len(candidate_pub_keys)}...", end='\r')
            
        for j, priv_cand in enumerate(priv_candidates):
            try:
                shared_point = get_shared_secret_point(priv_cand, pub_bytes)
                if shared_point:
                    shared_x = shared_point # shared_key is the x-coordinate bytes
                    
                    # Derivation candidates
                    derived_keys = []
                    derived_keys.append(hashlib.sha256(shared_x).digest()) # SHA256(x)
                    derived_keys.append(shared_x[:32]) # Raw X (if 32 bytes)
                    
                    # HKDF
                    try:
                        hkdf = HKDF(
                            algorithm=hashes.SHA256(),
                            length=32,
                            salt=None,
                            info=b'',
                        )
                        derived_keys.append(hkdf.derive(shared_x))
                    except: pass
                    
                    for k, key in enumerate(derived_keys):
                        # Try GCM
                        try:
                            aesgcm = AESGCM(key)
                            pt = aesgcm.decrypt(nonce, ciphertext, None)
                            if b"flag" in pt.lower() or b"ctf" in pt.lower() or b"Infosec" in pt:
                                log.success(f"FOUND FLAG! Pub[{i}], Priv[{j}], Derivation[{k}]")
                                log.success(f"Flag: {pt}")
                                return
                        except: pass
                        
                        # Try ChaCha
                        try:
                            chacha = ChaCha20Poly1305(key)
                            pt = chacha.decrypt(nonce, ciphertext, None)
                            if b"flag" in pt.lower() or b"ctf" in pt.lower() or b"Infosec" in pt:
                                log.success(f"FOUND FLAG! Pub[{i}], Priv[{j}], Derivation[{k}]")
                                log.success(f"Flag: {pt}")
                                return
                        except: pass

            except Exception:
                pass
                
    log.failure("Flag not found in candidates.")

if __name__ == "__main__":
    solve()
