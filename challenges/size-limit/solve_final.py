#!/usr/bin/env python3
"""
Size-Limit Challenge - Final Solver
====================================
El flag tiene 131 bytes, pero N solo soporta ~128 bytes.
La solución es que el flag tiene 3 bytes de leading zeros (NULL).
Esos bytes se pierden en bytes_to_long -> long_to_bytes.
"""

from Crypto.Util.number import long_to_bytes

# Datos del challenge
N = 65667982563395257456152578363358687414628050739860770903063206052667362178166666380390723634587933595241827767873104710537142458025201334420236653463444534018710274020834864080096247524541536313609304410859158429347482458882414275205742819080566766561312731091051276328620677195262137013588957713118640118673
e = 65537
c = 58443816925218320329602359198394095572237417576497896076618137604965419783093911328796166409276903249508047338019341719597113848471431947372873538253571717690982768328452282012361099369599755904288363602972252305949989677897650696581947849811037791349546750246816657184156675665729104603485387966759433211643
d = 14647215605104168233120807948419630020096019740227424951721591560155202409637919482865428659999792686501442518131270040719470657054982576354654918600616933355973824403026082055356501271036719280033851192012142309772828216012662939598631302504166489383155079998940570839539052860822636744356963005556392864865

# Descifrar
m = pow(c, d, N)
flag_bytes_raw = long_to_bytes(m)

print(f"[*] Decrypted bytes length: {len(flag_bytes_raw)}")

# El flag tiene exactamente 131 bytes - añadir leading nulls
expected_length = 131
null_padding = expected_length - len(flag_bytes_raw)
flag_bytes = b'\x00' * null_padding + flag_bytes_raw

print(f"[*] Padded to 131 bytes with {null_padding} leading NULLs")
print(f"[*] Hex: {flag_bytes.hex()}")
print()

# Ahora decodificar
try:
    flag = flag_bytes.decode('utf-8')
    print(f"[+] FLAG (UTF-8): {flag}")
except:
    try:
        flag = flag_bytes.decode('latin-1')
        print(f"[+] FLAG (Latin-1): {flag}")
    except:
        printable = ''.join(chr(b) if 32 <= b < 127 else '.' for b in flag_bytes)
        print(f"[*] Printable: {printable}")

# Mostrar sin los NULL iniciales
print(f"\n[*] Without leading NULLs: {flag_bytes.lstrip(b'\\x00')}")
print(f"[*] Repr: {repr(flag_bytes)}")

# El flag podría ser los bytes raw representados como hex string!
print(f"\n[*] If the flag is the hex string of decrypted data:")
print(f"    Length of hex: {len(flag_bytes_raw.hex())}")
print(f"    Hex: {flag_bytes_raw.hex()}")
