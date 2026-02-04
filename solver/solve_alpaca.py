
from pwn import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os

# Set up the connection
# nc 34.170.146.252 58209
HOST = '34.170.146.252'
PORT = 58209

def solve():
    try:
        # Establish connection
        r = remote(HOST, PORT)
        
        # Read the banner and the leaked key
        # Banner: "Welcome to my login service 🦙"
        # Key: "[DEBUG] key: <hex>"
        banner = r.recvline()
        print(f"Banner: {banner.decode().strip()}")
        
        key_line = r.recvline().decode().strip()
        print(f"Key Line: {key_line}")
        
        if "[DEBUG] key: " not in key_line:
            log.error("Failed to parse key line")
            return

        key_hex = key_line.split(": ")[1]
        key = bytes.fromhex(key_hex)
        log.info(f"Leaked Key: {key.hex()}")

        # Construct the target plaintext: 5 llamas
        # ALPACA = chr(129433) which is 🦙
        # Each 🦙 is 4 bytes in UTF-8: f0 9f a6 99
        # 5 * 4 = 20 bytes. 
        # AES block size is 16. So one full block (16) + 4 bytes.
        # Padding will add 12 bytes of value \x0c (12).
        alpaca_char = chr(129433)
        target_username = (alpaca_char * 5).encode('utf-8')
        log.info(f"Target Username bytes: {target_username.hex()}")
        
        padded_plaintext = pad(target_username, AES.block_size)
        log.info(f"Padded Plaintext: {padded_plaintext.hex()}")
        
        # Create a random IV
        iv = os.urandom(16)
        
        # Encrypt locally using the leaked key
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(padded_plaintext)
        
        log.info(f"Generated Ciphertext: {ciphertext.hex()}")
        log.info(f"Generated IV: {iv.hex()}")

        # Send ciphertext
        # Server expects: "Enter your ciphertext (hex): "
        r.recvuntil(b"Enter your ciphertext (hex): ")
        r.sendline(ciphertext.hex().encode())

        # Send IV
        # Server expects: "Enter your IV (hex): "
        r.recvuntil(b"Enter your IV (hex): ")
        r.sendline(iv.hex().encode())

        # Read the rest to get the flag
        # "Welcome, 🦙🦙🦙🦙🦙"
        # "Congratulations! Here is your flag: ..."
        response = r.recvall(timeout=2).decode(errors='ignore')
        print("Server Response:")
        print(response)
        
        if "Congratulations" in response:
            log.success("Attack Successful!")
            # Extract flag if possible or just rely on user seeing it
            for line in response.splitlines():
                if "ALPACA{" in line or "flag" in line.lower():
                    log.success(f"Flag might be in: {line}")
        else:
            log.failure("Attack Failed")

    except Exception as e:
        log.error(f"Error during solve: {e}")
    finally:
        r.close()

if __name__ == "__main__":
    solve()
