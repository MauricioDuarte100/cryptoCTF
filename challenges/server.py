import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

flag = os.environ.get("FLAG", "ALPACA{*** REDACTED ***}")

ALPACA = chr(129433)  # "🦙"
print(f"Welcome to my login service {ALPACA}")

key = os.urandom(16)

print(f"[DEBUG] key: {key.hex()}") # Oops!

try:
    ciphertext = bytes.fromhex(input("Enter your ciphertext (hex): "))
    iv = bytes.fromhex(input("Enter your IV (hex): "))

    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_plaintext, AES.block_size)
    username = plaintext.decode()

    print(f"Welcome, {username}")

    if username == ALPACA * 5:  # username == "🦙🦙🦙🦙🦙"
        print(f"Congratulations! Here is your flag: {flag}")
    else:
        print("Invalid username.")

except Exception as e:
    print(f"something went wrong: {e}")
    exit(1)
