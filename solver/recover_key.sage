
from sage.all import *

# secp256k1
p = 115792089237316195423570985008687907853269984665640564039457584007908834671663
a = 0
results = [{'b': 1, 'Px': 0, 'Py': 1, 'Sx': 0, 'Sy': 1}, {'b': 4, 'Px': 0, 'Py': 2, 'Sx': 0, 'Sy': 2}, {'b': 9, 'Px': 0, 'Py': 3, 'Sx': 0, 'Sy': 3}, {'b': 3, 'Px': 1, 'Py': 2, 'Sx': 29442590569047662184571181545702491538134006005499471238611640777753572254674, 'Sy': 38414353691963879954172447816133434326495127687587856495433295961265268934750}, {'b': 8, 'Px': 1, 'Py': 3, 'Sx': 85141419056133989808613652501605638315321401896259321665473753139168885977120, 'Sy': 91600374847618898734900016097518458532074599953178917475305269423723940164048}]

remainders = []
moduli = []

print(f"[*] Analyzing {len(results)} items...")

for item in results:
    try:
        b = item['b']
        Px, Py = item['Px'], item['Py']
        Sx, Sy = item['Sx'], item['Sy']
        
        # Define Curve
        E = EllipticCurve(GF(p), [a, b])
        P = E(Px, Py)
        # Handle S normalization if needed (server might return negative representation)
        S = E(Sx, Sy) 
        
        Q = P - S # Q = dP
        
        try:
            order = P.order()
        except:
            print(f"[-] Order calc failed for b={b}")
            continue
            
        print(f"[*] b={b}, Order={order}")
        factors = list(factor(order))
        print(f"    Factors: {factors}")
        
        largest_prime = factors[-1][0]
        if largest_prime > 10**16:
            print("    [-] Not smooth.")
            continue
            
        try:
            d_log = discrete_log(Q, P, operation='+')
            print(f"    [+] d = {d_log} (mod {order})")
            remainders.append(d_log)
            moduli.append(order)
        except Exception as e:
            print(f"    [-] DLP Error: {e}")
            
    except Exception as e:
        print(f"[-] Error: {e}")

if moduli:
    try:
        print("[*] Applying CRT...")
        d = crt(remainders, moduli)
        print(f"[+] d = {d}")
        print(f"[+] Hex: {hex(d)}")
        
        flag_candidate = int(d).to_bytes(256, 'big').lstrip(b'\0')
        print(f"[+] Flag bytes: {flag_candidate}")
        print(f"[+] Flag text: {flag_candidate.decode(errors='ignore')}")
    except Exception as e:
        print(f"[-] CRT Error: {e}")
else:
    print("[-] No moduli.")
