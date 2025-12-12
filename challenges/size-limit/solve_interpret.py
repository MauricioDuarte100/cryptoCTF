#!/usr/bin/env python3
"""
Size-Limit - More interpretations
"""
from Crypto.Util.number import long_to_bytes

N = 65667982563395257456152578363358687414628050739860770903063206052667362178166666380390723634587933595241827767873104710537142458025201334420236653463444534018710274020834864080096247524541536313609304410859158429347482458882414275205742819080566766561312731091051276328620677195262137013588957713118640118673
c = 58443816925218320329602359198394095572237417576497896076618137604965419783093911328796166409276903249508047338019341719597113848471431947372873538253571717690982768328452282012361099369599755904288363602972252305949989677897650696581947849811037791349546750246816657184156675665729104603485387966759433211643
d = 14647215605104168233120807948419630020096019740227424951721591560155202409637919482865428659999792686501442518131270040719470657054982576354654918600616933355973824403026082055356501271036719280033851192012142309772828216012662939598631302504166489383155079998940570839539052860822636744356963005556392864865

m = pow(c, d, N)
raw = long_to_bytes(m)

print("=== Raw decrypted bytes ===")
print(f"Length: {len(raw)}")
print(f"Hex: {raw.hex()}")
print()

# Interpretación 1: Es PKCS#1 v1.5 padding (00 02 ... 00 message)
# No parece, el primer byte es 01, no 00 02
print("=== Checking PKCS formats ===")
if raw[0:2] == b'\x00\x01':
    print("Looks like PKCS#1 type 1 (signature padding)")
    # Find the 0x00 separator
    idx = raw.find(b'\x00', 2)
    if idx > 0:
        message = raw[idx+1:]
        print(f"Message after PKCS separator: {message}")
elif raw[0:2] == b'\x00\x02':
    print("Looks like PKCS#1 type 2 (encryption padding)")
else:
    print(f"First two bytes: {raw[:2].hex()} - Not standard PKCS")

# Con leading zeros para llegar a 131 bytes
padded = b'\x00\x00\x00' + raw
print(f"\n=== With 3 leading zeros (131 bytes) ===")
print(f"Checking if starts with 00 01: {padded[0:2].hex()}")

# Si el texto plano tenía 00 00 00 al inicio, veamos qué sigue después
if padded[3:5] == b'\x01\xf7':
    print("Pattern: 00 00 00 01 f7 ...")
    # Quizás 01 es parte de algún encoding

# Interpretación: puede ser un file format o header?
print(f"\n=== As potential file magic ===")
print(f"First 16 bytes: {raw[:16].hex()}")

# El flag podría estar codificado en base32/36/58/64...?
import base64
print(f"\n=== Trying base64 decode of hex ===")
try:
    b64dec = base64.b64decode(raw.hex())
    print(f"Base64 decode of hex: {b64dec}")
except:
    print("Not valid base64")

# El flag es simplemente el formato: RTACTF{<hex>} ??
print(f"\n=== Potential format: RTACTF{{hex}} ===")
hex_flag = f"RTACTF{{{raw.hex()}}}"
print(f"Length: {len(hex_flag)}")
if len(hex_flag) == 131:
    print(f"[+] MATCH! Length is 131!")
    print(f"[+] FLAG: {hex_flag}")
else:
    print(f"Mismatch: {len(hex_flag)} != 131")

# Quizás sin el primer byte?
short_hex = raw[1:].hex()
hex_flag2 = f"RTACTF{{{short_hex}}}"
print(f"\nWithout first byte: length = {len(hex_flag2)}")
if len(hex_flag2) == 131:
    print(f"[+] MATCH!")
    print(f"[+] FLAG: {hex_flag2}")
