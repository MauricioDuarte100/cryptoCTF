"""
Script to register recently solved challenges into the Experience Storage.
"""

from src.learning.experience_storage import get_experience_storage, SolvedChallengeExperience
import uuid

def register_experiences():
    storage = get_experience_storage()
    print("🧠 Connected to Experience Storage")

    # 1. Convergent Cipher Experience
    convergent_exp = SolvedChallengeExperience(
        challenge_id=str(uuid.uuid4()),
        challenge_name="Convergent Cipher",
        challenge_description="Block cipher with 6-byte key and modular inverse S-box. Uses k0, k1, k2 derived from SHA256.",
        challenge_type="Block Cipher",
        difficulty="Medium",
        source_files=[],  # No source files stored here, but could read from file system
        server_host="tcp.flagyard.com",
        server_port=31850,
        solution_successful=True,
        attack_pattern="Differential Cryptanalysis",
        solution_steps=[
            "Analyze cipher structure: modular inverse is the only non-linear component",
            "Identify vulnerability: Differential Cryptanalysis possible with 2 chose plaintexts",
            "Send PT1 = all zeros to get baseline",
            "Send PT2 = flip LSB of each half to get differential trace",
            "Compute XOR of ciphertexts to eliminate k2",
            "Perform parallel Meet-in-the-Middle search for k0 and k1 that satisfy the differential equation",
            "Recover full key and decrypt flag"
        ],
        flag_found="FlagY{m33t_1n_th3_m1ddl3_0r_d1ff3r3n714l?}"
    )
    
    storage.store_experience(convergent_exp)
    print(f"✅ Registered: {convergent_exp.challenge_name}")

    # 2. VDF Challenge Experience
    vdf_exp = SolvedChallengeExperience(
        challenge_id=str(uuid.uuid4()),
        challenge_name="Wesolowski VDF Challenge",
        challenge_description="Verifiable Delay Function challenge based on exponentiation modulo n. Server proves result = g^(2^T) and asks for h, pi such that h = pi^l * g^r.",
        challenge_type="VDF",
        difficulty="Hard",
        source_files=[],
        server_host="tcp.flagyard.com",
        server_port=31850,
        solution_successful=True,
        attack_pattern="Algebraic Attack",
        solution_steps=[
            "Analyze verification equation: h % n == (pi^l * g^r) % n",
            "Observe server gives proof for 'result': result % n == (proof^l * g^r) % n",
            "Identify exploit: Protocol malleability allowing h = -result",
            "Set h = n - result (equivalent to -result mod n)",
            "Set pi = n - proof (equivalent to -proof mod n)",
            "Since l is an odd prime, (-proof)^l = -(proof^l), satisfying the equation",
            "Submit forged proof to retrieve flag"
        ],
        flag_found="FlagY{Wesolowski's_VDF_is_less_secure_in_Fiat-Shamir!}"
    )
    
    storage.store_experience(vdf_exp)
    print(f"✅ Registered: {vdf_exp.challenge_name}")

    # 3. Quadratic CRT Experience
    quadratic_exp = SolvedChallengeExperience(
        challenge_id=str(uuid.uuid4()),
        challenge_name="Quadratic CRT",
        challenge_description="CRT challenge over the ring of integers O of Q(sqrt(-7)). Flag encoded as flag*a where a=sqrt(-7). Given y1=x mod m1, y2=x mod m2.",
        challenge_type="Number Theory",
        difficulty="Hard",
        source_files=[],
        server_host="",
        server_port=0,
        solution_successful=True,
        attack_pattern="Quadratic Field CRT",
        solution_steps=[
            "Analyze that x = flag*a is purely imaginary in Q(sqrt(-7))",
            "Derive divisibility constraint: for m1|(c-d1)*a, need c ≡ d1 (mod N(m1)/gcd(m1b, 7*m1a))",
            "Reduce problem from O-CRT to standard Z-CRT",
            "Apply Chinese Remainder Theorem over integers",
            "Extract flag coefficient c from the CRT solution",
            "Decode c as 64-byte big-endian integer"
        ],
        flag_found="FlagY{qu4dr4t1c_1nt3g3rs_ar3_fun_abc360fd85fae6c0b1adf0d678ac41}"
    )
    
    storage.store_experience(quadratic_exp)
    print(f"✅ Registered: {quadratic_exp.challenge_name}")

    # 4. Ramson (Multi-layer encryption)
    ramson_exp = SolvedChallengeExperience(
        challenge_id=str(uuid.uuid4()),
        challenge_name="Ramson Multi-Layer Encryption",
        challenge_description="3-layer ransomware encryption: RSA (weak modulus), XOR with fixed key, ChaCha20 with known nonce.",
        challenge_type="Multi-Layer Crypto",
        difficulty="Easy",
        source_files=[],
        server_host="",
        server_port=0,
        solution_successful=True,
        attack_pattern="Layer-by-layer Decryption",
        solution_steps=[
            "Analyze encryption layers: RSA -> XOR -> ChaCha20",
            "Note RSA private key (d, n) is provided in source code",
            "Decrypt RSA: each ciphertext c maps to plaintext char via pow(c, d, n)",
            "Decode base64 to get XOR'd key bytes",
            "Reverse XOR with key '0x1337' (cycling pattern)",
            "Use recovered ChaCha20 key with provided nonce to decrypt flag"
        ],
        flag_found="FlagY{Hybr!d_Encryp7i0n_Fl4g}"
    )
    storage.store_experience(ramson_exp)
    print(f"✅ Registered: {ramson_exp.challenge_name}")

    # 5. Leaky RSA (Bellcore fault attack)
    leaky_exp = SolvedChallengeExperience(
        challenge_id=str(uuid.uuid4()),
        challenge_name="Leaky RSA Signatures",
        challenge_description="RSA with partial signatures s1, s2 for message 'an arbitrary message'. Standard Bellcore attack with SHA-256 hash.",
        challenge_type="RSA",
        difficulty="Medium",
        source_files=[],
        server_host="",
        server_port=0,
        solution_successful=True,
        attack_pattern="Bellcore Fault Attack",
        solution_steps=[
            "Identify partial signatures s1, s2 are CRT half-signatures",
            "Note that raw message doesn't work - try SHA-256 hash",
            "Compute m = SHA256(msg) as integer",
            "Calculate gcd(s1^e - m, n) to find factor p",
            "Factor n = p * q, compute phi and private key d",
            "Decrypt ciphertext c to recover flag"
        ],
        flag_found="FlagY{f6fdd9f8ac38f5397731a3be3856c904}"
    )
    storage.store_experience(leaky_exp)
    print(f"✅ Registered: {leaky_exp.challenge_name}")

    # 6. Tux BMP XOR Encryption
    tux_exp = SolvedChallengeExperience(
        challenge_id=str(uuid.uuid4()),
        challenge_name="Tux BMP XOR Encryption",
        challenge_description="BMP image encrypted with simple XOR cipher. Known BMP header enables key recovery.",
        challenge_type="Classical Cipher",
        difficulty="Easy",
        source_files=[],
        server_host="",
        server_port=0,
        solution_successful=True,
        attack_pattern="Known Plaintext Attack",
        solution_steps=[
            "Identify encrypted BMP file (tux.bmp.enc)",
            "Build expected BMP header (magic 'BM', file size, offsets)",
            "XOR encrypted header with expected header to derive key",
            "Identify key pattern repeats every 2 bytes (0xbd3a)",
            "Decrypt entire file with repeating 2-byte XOR key",
            "Visual flag may be embedded in image"
        ],
        flag_found="Visual flag in decrypted image"
    )
    storage.store_experience(tux_exp)
    print(f"✅ Registered: {tux_exp.challenge_name}")

    # 7. Simple Encryption (XOR Stream Cipher)
    simple_enc_exp = SolvedChallengeExperience(
        challenge_id=str(uuid.uuid4()),
        challenge_name="Simple XOR Stream Encryption",
        challenge_description="Custom stream cipher: o[i+2] = ((key*o[i+1]) ^ (key+(o[i]*p))) % 2^128. Key is 64-bit secret.",
        challenge_type="Stream Cipher",
        difficulty="Medium",
        source_files=[],
        server_host="",
        server_port=0,
        solution_successful=True,
        attack_pattern="Algebraic Key Recovery",
        solution_steps=[
            "Analyze cipher structure: XOR of key*prev with key+prev2*char",
            "Set up Z3 constraint for first equation with known o[0], o[1], o[2]",
            "Add second equation constraint for o[3]",
            "Try common flag prefix 'Fl' to narrow key search",
            "Z3 solves for unique key = 17608713827523745640",
            "Brute-force each character position using forward encryption verification"
        ],
        flag_found="FlagY{e4sy_3nc_3asy_d3c_a6cebdf01bf8a8feb61f}"
    )
    storage.store_experience(simple_enc_exp)
    print(f"✅ Registered: {simple_enc_exp.challenge_name}")

    print("\n🎉 All new experiences stored successfully!")

if __name__ == "__main__":
    register_experiences()
