import os
import hashlib
from Crypto.Util.number import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

flag = os.environ.get("FLAG", "Alpaca{dummy}").encode()

# You don't need to focus on encrypt_flag/decrypt_flag :)
def encrypt_flag(pt, params):
    key = hashlib.sha256(str(params).encode()).digest()
    cipher = AES.new(key, AES.MODE_CBC)
    return cipher.iv + cipher.encrypt(pad(pt, 16))

def decrypt_flag(ct, params):
    key = hashlib.sha256(str(params).encode()).digest()
    cipher = AES.new(key, AES.MODE_CBC, iv=ct[:16])
    return unpad(cipher.decrypt(ct[16:]), 16)

class LCG:
    def __init__(self):
        self.p = getPrime(64)
        self.a = getRandomRange(1, self.p)
        self.b = getRandomRange(1, self.p)
        self.s = getRandomRange(1, self.p)

    def serve_coffee(self):
        self.s = (self.a * self.s + self.b) % self.p
        return self.s


lcg = LCG()
enc_flag = encrypt_flag(flag, (lcg.p, lcg.a, lcg.b, lcg.s)).hex()

print("#1 order:", lcg.serve_coffee())
print("#2 order:", lcg.serve_coffee())
print("#3 order:", lcg.serve_coffee())
print("#4 order:", lcg.serve_coffee())
# If you can recover p, a, b, and s, you can get the flag using decrypt_flag(bytes.fromhex(enc_flag), (p, a, b, s))!
print("encrypted flag:", enc_flag)
