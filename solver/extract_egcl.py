import re
from hashlib import sha256
from Crypto.Util.number import bytes_to_long
from fastecdsa.curve import secp256k1

q = secp256k1.q

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
    with open("challenges/egcl/output_2b76e1402ecd70095a243a705fbc9b17.txt", "r") as f:
        content = f.read()
    
    # Extract sigs list
    sigs_match = re.search(r"sigs = \[(.*?)\]", content, re.DOTALL)
    if not sigs_match:
        print("Sigs not found")
        return

    sigs_str = sigs_match.group(1)
    # Parse the tuples
    # Remove parens and split by "), ("
    sigs = eval(f"[{sigs_str}]")
    
    data = []
    for m, (r, s) in zip(msgs, sigs):
        z = bytes_to_long(sha256(m).digest()) % q
        data.append({'z': z, 'r': r, 's': s})
    
    return data

if __name__ == "__main__":
    data = get_data()
    print(f"Loaded {len(data)} signatures")
    for i, d in enumerate(data[:3]):
        print(f"Msg {i}: z={d['z']}, r={d['r']}, s={d['s']}")
