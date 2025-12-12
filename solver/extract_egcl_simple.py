import re
from hashlib import sha256
from Crypto.Util.number import bytes_to_long

# secp256k1 order q
q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

msgs = [
    b"https://www.youtube.com/watch?v=kv4UD4ICd_0",
    b"https://www.youtube.com/watch?v=IijOKxLclxE",
    b"https://www.youtube.com/watch?v=GH6akWYAtGc",
    b"https://www.youtube.com/watch?v=Y3JhUFAa9bk",
    b"https://www.youtube.com/watch?v=FGID8CJ1fUY",
    b"https://www.youtube.com/watch?v=_BfmEjHVYwM",
    b"https://www.youtube.com/watch?v=zH7wBliAhT0",
    b"https://www.youtube.com/watch?v=NROQyBPX9Uo",
    b"https://www.youtube.com/watch?v=ylH6VpJAoME",
    b"https://www.youtube.com/watch?v=hI34Bhf5SaY",
    b"https://www.youtube.com/watch?v=bef23j792eE",
    b"https://www.youtube.com/watch?v=ybvXNOWX-dI",
    b"https://www.youtube.com/watch?v=dt3p2HtLzDA",
    b"https://www.youtube.com/watch?v=1Z4O8bKoLlU",
    b"https://www.youtube.com/watch?v=S53XDR4eGy4",
    b"https://www.youtube.com/watch?v=ZK64DWBQNXw",
    b"https://www.youtube.com/watch?v=tLL8cqRmaNE",
]

def get_data():
    try:
        with open("challenges/egcl/output_2b76e1402ecd70095a243a705fbc9b17.txt", "r") as f:
            content = f.read()
            
        sigs_match = re.search(r"sigs = \[(.*?)\]", content, re.DOTALL)
        if not sigs_match:
            print("Sigs not found")
            return
            
        sigs_str = sigs_match.group(1)
        sigs = eval(f"[{sigs_str}]")
        
        print("data = [")
        for m, (r, s) in zip(msgs, sigs):
            z = bytes_to_long(sha256(m).digest()) % q
            print(f"    {{'z': {z}, 'r': {r}, 's': {s}}},")
        print("]")
        
        # Check ct and nonce
        ct_match = re.search(r"ct = (b'.*?')", content)
        nonce_match = re.search(r"nonce = (b'.*?')", content)
        if ct_match:
            print(f"ct = {ct_match.group(1)}")
        if nonce_match:
            print(f"nonce = {nonce_match.group(1)}")

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    get_data()
