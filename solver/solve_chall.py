from pwn import *
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
import binascii
import os

# Set up the connection
HOST = 'remote.infoseciitr.in'
PORT = 4004

def solve():
    # context.log_level = 'debug'
    r = remote(HOST, PORT)

    # Receive the banner
    r.recvuntil(b"Choose an option:")

    # Step 1: Get the key and nonce (Option 2)
    r.sendline(b"2")
    r.recvuntil(b"KEYS=['")
    key_hex = r.recvuntil(b"']", drop=True).decode()
    r.recvuntil(b"nonce=")
    nonce_hex = r.recvline().strip().decode()

    print(f"[*] Leaked Key: {key_hex}")
    print(f"[*] Leaked Nonce: {nonce_hex}")

    key = binascii.unhexlify(key_hex)
    nonce = binascii.unhexlify(nonce_hex)

    # Step 2: Construct the plaintext
    # The server decrypts 4 chunks of 16 bytes each and concatenates them.
    # We need the final result to be "gib me flag plis"
    # The loop index i goes from 0 to 3.
    # text = decrypt(ct, key)[16*i : 16*(i+1)]
    # So we need to construct a single ciphertext that decrypts to a 64-byte block
    # where each 16-byte chunk corresponds to a part of our desired message.
    
    # Target message: "gib me flag plis" (16 chars)
    # But wait, the server does:
    # usertext += service.decrypt(ct, key)[16 * i:16 * (i+1)]
    # It uses the SAME ciphertext 'ct' for all 4 iterations?
    # Yes: ct = binascii.unhexlify(CIPHERTEXTS[i % len(CIPHERTEXTS)])
    # If we only push 1 ciphertext, it uses that same ciphertext for all i=0,1,2,3.
    # And it slices the DECRYPTED text: [16*i : 16*(i+1)]
    # So the decrypted plaintext must be at least 16*4 = 64 bytes long.
    # And:
    # Chunk 0 (0-16): "gib me flag plis" ? No, the target is "gib me flag plis" TOTAL.
    # Let's look at the server code again.
    # usertext += text
    # if usertext == REQUEST: ... REQUEST = "gib me flag plis"
    # So usertext must be "gib me flag plis".
    # But the loop runs 4 times.
    # So we need to split "gib me flag plis" into 4 chunks?
    # "gib me flag plis" is 16 bytes.
    # 16 / 4 = 4 bytes per chunk?
    # No, the slice is [16*i : 16*(i+1)]. That is a 16-byte slice.
    # So each iteration appends 16 bytes to usertext.
    # So usertext will be 16 * 4 = 64 bytes long?
    # But REQUEST is "gib me flag plis" (16 bytes).
    # If usertext is 64 bytes, it will never equal REQUEST.
    # Wait.
    # text = service.decrypt(...)[...].strip()
    # Ah! .strip() removes whitespace.
    # So we can pad our chunks with spaces, and they will be stripped.
    # But usertext += text.
    # If we want usertext to be "gib me flag plis", we can distribute it across the 4 chunks.
    # Chunk 0: "gib " (padded) -> strips to "gib" ? No, "gib me flag plis" has spaces.
    # Let's see.
    # We want usertext = "gib me flag plis"
    # We have 4 iterations.
    # We can make:
    # Iter 0: "gib "
    # Iter 1: "me "
    # Iter 2: "flag "
    # Iter 3: "plis"
    # But the slice is 16 bytes.
    # And .strip() is called on the result.
    # So if we have "gib             ", strip() -> "gib".
    # But "gib " (with a space) strip() -> "gib". We lose the space.
    # Wait, REQUEST has spaces. "gib me flag plis".
    # If we strip, we lose leading/trailing spaces.
    # So "gib " becomes "gib".
    # So usertext would be "gib" + "me" + "flag" + "plis" = "gibmeflagplis".
    # That does not match "gib me flag plis".
    # UNLESS... the slice contains the space in the middle?
    # "gib me          " -> strip() -> "gib me".
    # So we can put "gib me flag plis" all in the first chunk?
    # Iter 0: "gib me flag plis" (16 bytes).
    # Iter 1: "" (empty) -> strip() -> empty string.
    # Iter 2: ""
    # Iter 3: ""
    # Code: if not text or len(text) == 0: print("why so rude :("); exit(0)
    # So we CANNOT have empty chunks after strip().
    # So we must have at least 1 char in each chunk.
    # And the total concatenation must be "gib me flag plis".
    # "gib me flag plis" length is 16.
    # We have 4 chunks.
    # Chunk 0: "gib " -> strip -> "gib" (lost space)
    # This is tricky.
    # "gib me flag plis"
    # Indices:
    # g i b   m e   f l a g   p l i s
    # 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5
    #
    # Maybe we can split it like:
    # 1. "gib " -> strip -> "gib" (fail)
    # What if we use non-strippable whitespace? No, strip() removes all whitespace.
    # What if we put the space in the middle of a chunk?
    # Chunk 0: "gib m" (5 chars) + padding -> strip -> "gib m"
    # Chunk 1: "e fl" (4 chars) + padding -> strip -> "e fl"
    # Chunk 2: "ag p" (4 chars) + padding -> strip -> "ag p"
    # Chunk 3: "lis" (3 chars) + padding -> strip -> "lis"
    # Total: "gib m" + "e fl" + "ag p" + "lis" = "gib me flag plis"
    # This works!
    # So we need to construct a 64-byte plaintext where:
    # Bytes 0-16: "gib m" + padding
    # Bytes 16-32: "e fl" + padding
    # Bytes 32-48: "ag p" + padding
    # Bytes 48-64: "lis" + padding
    
    p1 = b"gib m".ljust(16, b'\x00') # strip() removes whitespace, but does it remove null bytes?
    # Python's .strip() removes whitespace characters. Null byte is NOT whitespace in Python string (unicode), 
    # but here we are decoding to utf-8 first.
    # .decode('utf-8').strip()
    # \x00 is not whitespace. So it won't be stripped.
    # So we should pad with spaces?
    # If we pad with spaces: "gib m           " -> strip() -> "gib m". Correct.
    
    p1 = b"gib m".ljust(16, b' ')
    p2 = b"e fl".ljust(16, b' ')
    p3 = b"ag p".ljust(16, b' ')
    p4 = b"lis".ljust(16, b' ')
    
    plaintext = p1 + p2 + p3 + p4
    
    # Encrypt
    aesgcm = AESGCMSIV(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, b"")
    
    ct_hex = binascii.hexlify(ciphertext).decode()
    print(f"[*] Crafted Ciphertext: {ct_hex}")
    
    # Step 3: Push ciphertext (Option 3)
    r.sendline(b"3")
    r.sendline(ct_hex.encode())
    
    # Step 4: Request flag (Option 4)
    r.sendline(b"4")
    
    # Read flag
    r.recvuntil(b"Here is the flag: ")
    flag = r.recvline().strip().decode()
    print(f"\n[+] FLAG: {flag}")
    r.close()

if __name__ == "__main__":
    solve()
