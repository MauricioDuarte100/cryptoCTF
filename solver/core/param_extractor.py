#!/usr/bin/env python3
"""
Crypto Parameter Extractor
===========================

Robust multi-format extraction of cryptographic parameters from challenge code.
Supports RSA, ECDSA, ECC, AES, Hash, and Lattice challenge types.
"""

import re
from typing import Dict, Any, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Regex helpers
# ---------------------------------------------------------------------------

# Matches a possibly-multi-line integer literal (decimal, hex, or Python int())
_INT_DEC = r'(\d+)'                                       # any decimal integer
_INT_HEX = r'(0[xX][0-9a-fA-F_]+)'                        # 0x...
_INT_PY  = r"int\(\s*['\"]([0-9a-fA-F]+)['\"]\s*,\s*16\s*\)"  # int('abc',16)
_INT_ANY = rf'(?:{_INT_HEX}|{_INT_PY}|{_INT_DEC})'

# Common variable name aliases per parameter
_RSA_ALIASES: Dict[str, List[str]] = {
    "n":   ["n", "N", "modulus", "mod", "public_key", "pub_key", "rsa_n"],
    "e":   ["e", "E", "exp", "exponent", "public_exponent", "pub_exp", "rsa_e"],
    "c":   ["c", "C", "ct", "ciphertext", "cipher", "enc", "encrypted", "cipher_text", "rsa_c"],
    "p":   ["p", "P", "prime1", "factor1"],
    "q":   ["q", "Q", "prime2", "factor2"],
    "d":   ["d", "D", "private_key", "priv_key", "secret", "private_exponent"],
    "phi": ["phi", "totient", "euler_totient", "phi_n"],
    "dp":  ["dp", "dP", "d_p", "exp1"],
    "dq":  ["dq", "dQ", "d_q", "exp2"],
}

_ECC_ALIASES: Dict[str, List[str]] = {
    "p":     ["p", "P", "prime", "field_prime", "modulus"],
    "a":     ["a", "A", "curve_a"],
    "b":     ["b", "B", "curve_b"],
    "order": ["order", "curve_order", "group_order", "ord", "curve_n"],
    "Gx":    ["Gx", "gx", "gen_x", "generator_x"],
    "Gy":    ["Gy", "gy", "gen_y", "generator_y"],
    "Qx":    ["Qx", "qx", "pub_x", "pubkey_x"],
    "Qy":    ["Qy", "qy", "pub_y", "pubkey_y"],
}

_AES_ALIASES: Dict[str, List[str]] = {
    "key":        ["key", "KEY", "aes_key", "secret_key", "k"],
    "iv":         ["iv", "IV", "nonce", "NONCE", "initialization_vector"],
    "ciphertext": ["ct", "ciphertext", "cipher_text", "encrypted", "enc", "cipher"],
    "tag":        ["tag", "TAG", "auth_tag", "mac"],
}


def _parse_int(raw: str) -> Optional[int]:
    """Parse a string that may be decimal, hex, or contain underscores."""
    raw = raw.strip().replace("_", "")
    try:
        if raw.startswith(("0x", "0X")):
            return int(raw, 16)
        return int(raw)
    except ValueError:
        return None


def _find_var_value(code: str, names: List[str]) -> Optional[int]:
    """Find the first matching variable assignment and return its integer value."""
    for name in names:
        # Pattern: name = <int>  (with possible spaces, newlines in value)
        # Supports: var = 0xABC, var = 123, var = int('abc', 16)
        escaped = re.escape(name)
        # Match exact variable name (word boundary)
        patterns = [
            # Direct assignment: name = 12345 or name = 0xABC
            rf'(?:^|[\s;,])({escaped})\s*=\s*{_INT_ANY}',
            # Python int() form: name = int('abc', 16)
            rf'(?:^|[\s;,])({escaped})\s*=\s*{_INT_PY}',
        ]
        for pat in patterns:
            match = re.search(pat, code, re.MULTILINE)
            if match:
                # Find the integer group (first non-None capture after var name)
                groups = match.groups()
                for g in groups[1:]:  # skip the var name group
                    if g is not None:
                        val = _parse_int(g)
                        if val is not None:
                            return val
    return None


def _find_hex_strings(code: str) -> List[str]:
    """Find hex-encoded strings in quotes."""
    return re.findall(r'["\']([0-9a-fA-F]{16,})["\']', code)


def _find_bytes_literals(code: str) -> List[bytes]:
    """Find b'...' or bytes.fromhex('...') patterns."""
    results = []
    # bytes.fromhex('...')
    for m in re.finditer(r"bytes\.fromhex\(\s*['\"]([0-9a-fA-F]+)['\"]\s*\)", code):
        try:
            results.append(bytes.fromhex(m.group(1)))
        except ValueError:
            pass
    # b'\x...' -- harder to parse reliably, skip for now
    return results


def _find_tuple(code: str, name: str) -> Optional[Tuple[int, int]]:
    """Find a named tuple assignment like G = (x, y)."""
    escaped = re.escape(name)
    pat = rf'{escaped}\s*=\s*\(\s*{_INT_ANY}\s*,\s*{_INT_ANY}\s*\)'
    match = re.search(pat, code, re.MULTILINE)
    if match:
        groups = [g for g in match.groups() if g is not None]
        if len(groups) >= 2:
            x = _parse_int(groups[0])
            y = _parse_int(groups[1])
            if x is not None and y is not None:
                return (x, y)
    return None


# ---------------------------------------------------------------------------
# CryptoParamExtractor
# ---------------------------------------------------------------------------

class CryptoParamExtractor:
    """Extracts cryptographic parameters from challenge source code."""

    def extract_all(self, code: str) -> Dict[str, Any]:
        """
        Extract all detectable crypto parameters from code.

        Returns:
            {
                "rsa": { "n": ..., "e": ..., "c": ..., ... } or {},
                "ecc": { "p": ..., "a": ..., "G": ..., ... } or {},
                "ecdsa": { "signatures": [...], ... } or {},
                "aes": { "key": ..., "iv": ..., "mode": ..., ... } or {},
                "hash": { "algorithm": ..., "target": ..., ... } or {},
                "lattice": { "detected": True/False, ... },
                "detected_type": "RSA" | "ECC" | ... | "Unknown",
                "hex_values": [...],
                "raw_params": { ... },  # flat dict of all found params
            }
        """
        result: Dict[str, Any] = {}

        result["rsa"] = self._extract_rsa(code)
        result["ecc"] = self._extract_ecc(code)
        result["ecdsa"] = self._extract_ecdsa(code)
        result["aes"] = self._extract_aes(code)
        result["hash"] = self._extract_hash(code)
        result["lattice"] = self._extract_lattice(code)
        result["hex_values"] = _find_hex_strings(code)
        result["detected_type"] = self._detect_type(code, result)

        # Flat dict for backward compatibility with auto_solve.py
        raw = {}
        for section in ["rsa", "ecc", "aes"]:
            for k, v in result.get(section, {}).items():
                if v is not None:
                    raw[k] = v
        result["raw_params"] = raw

        return result

    # --- RSA ---

    def _extract_rsa(self, code: str) -> Dict[str, Any]:
        params: Dict[str, Any] = {}
        for param, aliases in _RSA_ALIASES.items():
            val = _find_var_value(code, aliases)
            if val is not None:
                params[param] = val

        # Detect multiple ciphertexts (Hastad broadcast)
        c_list = re.findall(r'c\d+\s*=\s*' + _INT_ANY, code)
        if len(c_list) >= 2:
            params["multi_ct"] = True
            params["ct_count"] = len(c_list)

        # Detect multiple moduli
        n_list = re.findall(r'n\d+\s*=\s*' + _INT_ANY, code)
        if len(n_list) >= 2:
            params["multi_n"] = True
            params["n_count"] = len(n_list)

        # Detect multiple exponents (common modulus)
        e_list = re.findall(r'e\d+\s*=\s*' + _INT_ANY, code)
        if len(e_list) >= 2:
            params["multi_e"] = True
            params["e_count"] = len(e_list)

        # Compute derived features for early-exit
        if "n" in params:
            params["n_bits"] = params["n"].bit_length()
        if "e" in params:
            params["e_bits"] = params["e"].bit_length()

        return params

    # --- ECC ---

    def _extract_ecc(self, code: str) -> Dict[str, Any]:
        params: Dict[str, Any] = {}

        for param, aliases in _ECC_ALIASES.items():
            val = _find_var_value(code, aliases)
            if val is not None:
                params[param] = val

        # Generator point G = (x, y)
        for name in ["G", "generator", "gen", "base_point"]:
            pt = _find_tuple(code, name)
            if pt:
                params["G"] = pt
                break

        # Public key Q = (x, y)
        for name in ["Q", "P", "pub", "public_key", "pubkey"]:
            pt = _find_tuple(code, name)
            if pt:
                params["Q"] = pt
                break

        # Named curves
        curve_names = [
            "secp256k1", "secp256r1", "secp384r1", "secp521r1",
            "P-256", "P-384", "P-521", "ed25519", "Curve25519",
            "brainpoolP256r1", "brainpoolP384r1",
        ]
        code_lower = code.lower()
        for cn in curve_names:
            if cn.lower() in code_lower:
                params["curve_name"] = cn
                break

        return params

    # --- ECDSA ---

    def _extract_ecdsa(self, code: str) -> Dict[str, Any]:
        params: Dict[str, Any] = {}

        # Find (r, s) signature pairs
        sig_pattern = r'\(\s*' + _INT_ANY + r'\s*,\s*' + _INT_ANY + r'\s*\)'
        sigs = re.findall(sig_pattern, code)
        if sigs:
            parsed_sigs = []
            for groups in sigs:
                vals = [_parse_int(g) for g in groups if g is not None]
                if len(vals) >= 2:
                    parsed_sigs.append((vals[0], vals[1]))
            if parsed_sigs:
                params["signatures"] = parsed_sigs
                params["sig_count"] = len(parsed_sigs)

                # Check for nonce reuse (same r value)
                r_values = [s[0] for s in parsed_sigs]
                if len(r_values) != len(set(r_values)):
                    params["nonce_reuse_detected"] = True

        # Hash values (z)
        for name in ["z", "z1", "z2", "hash_val", "msg_hash"]:
            val = _find_var_value(code, [name])
            if val is not None:
                params.setdefault("z_values", []).append(val)

        # Curve order n
        for name in ["n", "order", "curve_order", "q"]:
            val = _find_var_value(code, [name])
            if val is not None and val > 2**100:  # likely a curve order, not RSA
                params["curve_order"] = val
                break

        return params

    # --- AES ---

    def _extract_aes(self, code: str) -> Dict[str, Any]:
        params: Dict[str, Any] = {}

        # Key/IV/nonce from hex strings
        for param, aliases in _AES_ALIASES.items():
            val = _find_var_value(code, aliases)
            if val is not None:
                params[param] = val

        # Hex-encoded key/iv
        hex_vals = _find_hex_strings(code)
        for hv in hex_vals:
            byte_len = len(hv) // 2
            if byte_len == 16 and "key" not in params:
                params.setdefault("possible_key_or_iv", []).append(hv)
            elif byte_len == 32 and "key" not in params:
                params.setdefault("possible_key_or_iv", []).append(hv)

        # Detect mode
        code_lower = code.lower()
        modes = {
            "ECB": ["ecb", "aes.mode_ecb", "mode_ecb"],
            "CBC": ["cbc", "aes.mode_cbc", "mode_cbc"],
            "CTR": ["ctr", "aes.mode_ctr", "mode_ctr"],
            "GCM": ["gcm", "aes.mode_gcm", "mode_gcm"],
            "CFB": ["cfb", "aes.mode_cfb", "mode_cfb"],
            "OFB": ["ofb", "aes.mode_ofb", "mode_ofb"],
        }
        for mode_name, keywords in modes.items():
            if any(kw in code_lower for kw in keywords):
                params["mode"] = mode_name
                break

        # bytes.fromhex patterns for ciphertext/iv
        byte_literals = _find_bytes_literals(code)
        for bl in byte_literals:
            if len(bl) == 16:
                params.setdefault("byte_blocks_16", []).append(bl.hex())
            elif len(bl) > 16:
                params.setdefault("byte_blocks_long", []).append(bl.hex())

        return params

    # --- Hash ---

    def _extract_hash(self, code: str) -> Dict[str, Any]:
        params: Dict[str, Any] = {}
        code_lower = code.lower()

        # Detect hash algorithm
        algorithms = {
            "SHA256": ["sha256", "sha-256"],
            "SHA1":   ["sha1", "sha-1"],
            "SHA512": ["sha512", "sha-512"],
            "MD5":    ["md5"],
            "SHA3":   ["sha3", "sha-3", "keccak"],
            "BLAKE2": ["blake2"],
        }
        for algo, keywords in algorithms.items():
            if any(kw in code_lower for kw in keywords):
                params["algorithm"] = algo
                break

        # Target hash value
        hash_patterns = [
            r'target\s*=\s*["\']([0-9a-fA-F]{32,128})["\']',
            r'hash_value\s*=\s*["\']([0-9a-fA-F]{32,128})["\']',
            r'expected\s*=\s*["\']([0-9a-fA-F]{32,128})["\']',
        ]
        for pat in hash_patterns:
            m = re.search(pat, code)
            if m:
                params["target_hash"] = m.group(1)
                break

        # Detect length extension indicators
        if "hmac" not in code_lower and any(
            kw in code_lower for kw in ["append", "extend", "length_extension", "hash_oracle"]
        ):
            params["possible_length_extension"] = True

        return params

    # --- Lattice ---

    def _extract_lattice(self, code: str) -> Dict[str, Any]:
        params: Dict[str, Any] = {}
        code_lower = code.lower()

        lattice_keywords = ["lll", "bkz", "lattice", "cvp", "svp", "shortest_vector",
                            "closest_vector", "hnp", "hidden_number", "coppersmith",
                            "small_roots", "matrix("]
        params["detected"] = any(kw in code_lower for kw in lattice_keywords)

        # Detect matrix dimensions
        dim_match = re.search(r'matrix.*?(\d+)\s*[xX,]\s*(\d+)', code)
        if dim_match:
            params["rows"] = int(dim_match.group(1))
            params["cols"] = int(dim_match.group(2))

        return params

    # --- Type detection ---

    def _detect_type(self, code: str, extracted: Dict) -> str:
        """Detect the most likely crypto type based on extracted parameters."""
        scores: Dict[str, float] = {}
        code_lower = code.lower()

        # RSA signals
        rsa = extracted.get("rsa", {})
        rsa_score = 0
        if rsa.get("n") and rsa.get("e"):
            rsa_score += 3
        if rsa.get("c"):
            rsa_score += 2
        if rsa.get("p") or rsa.get("q"):
            rsa_score += 1
        if any(kw in code_lower for kw in ["rsa", "factor", "prime", "phi"]):
            rsa_score += 1
        scores["RSA"] = rsa_score

        # ECC signals
        ecc = extracted.get("ecc", {})
        ecc_score = 0
        if ecc.get("G") or ecc.get("curve_name"):
            ecc_score += 3
        if ecc.get("a") is not None and ecc.get("b") is not None:
            ecc_score += 2
        if any(kw in code_lower for kw in ["elliptic", "curve", "ecc", "point"]):
            ecc_score += 1
        scores["ECC"] = ecc_score

        # ECDSA signals
        ecdsa = extracted.get("ecdsa", {})
        ecdsa_score = 0
        if ecdsa.get("signatures"):
            ecdsa_score += 3
        if ecdsa.get("nonce_reuse_detected"):
            ecdsa_score += 2
        if any(kw in code_lower for kw in ["ecdsa", "dsa", "sign", "signature"]):
            ecdsa_score += 2
        scores["ECDSA"] = ecdsa_score

        # AES signals
        aes = extracted.get("aes", {})
        aes_score = 0
        if aes.get("mode"):
            aes_score += 3
        if aes.get("key") or aes.get("iv"):
            aes_score += 2
        if any(kw in code_lower for kw in ["aes", "block cipher", "padding"]):
            aes_score += 1
        scores["AES"] = aes_score

        # Hash signals
        hash_params = extracted.get("hash", {})
        hash_score = 0
        if hash_params.get("algorithm"):
            hash_score += 2
        if hash_params.get("target_hash"):
            hash_score += 2
        if any(kw in code_lower for kw in ["hash", "sha", "md5", "digest"]):
            hash_score += 1
        scores["Hash"] = hash_score

        # Lattice signals
        lattice = extracted.get("lattice", {})
        lattice_score = 0
        if lattice.get("detected"):
            lattice_score += 3
        scores["Lattice"] = lattice_score

        # XOR signals
        xor_score = 0
        if any(kw in code_lower for kw in ["xor", "otp", "stream_cipher"]):
            xor_score += 2
        if re.search(r'\^', code):
            xor_score += 0.5
        scores["XOR"] = xor_score

        # Classical signals
        classical_score = 0
        if any(kw in code_lower for kw in ["caesar", "vigenere", "substitution", "rot13", "affine"]):
            classical_score += 3
        scores["Classical"] = classical_score

        # Pick best
        if not scores or max(scores.values()) == 0:
            return "Unknown"

        return max(scores, key=scores.get)


# ---------------------------------------------------------------------------
# EarlyExitChecker
# ---------------------------------------------------------------------------

class EarlyExitChecker:
    """Quick applicability checks for solver modules."""

    @staticmethod
    def rsa_attacks_order(params: Dict[str, Any]) -> List[str]:
        """
        Return RSA attacks sorted by likelihood of success.

        Args:
            params: RSA parameters from CryptoParamExtractor

        Returns:
            Ordered list of attack names to try
        """
        attacks = []
        n_bits = params.get("n_bits", 0)
        e = params.get("e", 65537)
        e_bits = params.get("e_bits", 17)

        # Multi-ciphertext -> Hastad
        if params.get("multi_ct") and params.get("multi_n") and e <= 17:
            attacks.append("hastad_broadcast")

        # Multi-exponent same N -> Common Modulus
        if params.get("multi_e"):
            attacks.append("common_modulus")

        # Small e
        if e <= 5:
            attacks.append("small_e_root")

        # Very large e relative to n -> Wiener
        if e_bits > 0 and n_bits > 0 and e_bits > n_bits // 4:
            attacks.append("wiener")

        # Small n -> trial division
        if 0 < n_bits <= 256:
            attacks.append("trial_division")

        # Medium n -> Fermat
        if 0 < n_bits <= 512:
            attacks.append("fermat")

        # CRT leak (dp, dq present)
        if params.get("dp") or params.get("dq"):
            attacks.append("crt_leak")

        # Always try as fallback
        if "wiener" not in attacks:
            attacks.append("wiener")
        attacks.append("pollard_p1")
        attacks.append("pollard_rho")

        return attacks

    @staticmethod
    def ecdsa_attacks_order(params: Dict[str, Any]) -> List[str]:
        """Return ECDSA attacks sorted by likelihood."""
        attacks = []

        if params.get("nonce_reuse_detected"):
            attacks.append("nonce_reuse")

        sig_count = params.get("sig_count", 0)
        if sig_count >= 3:
            attacks.append("biased_nonce_hnp")

        attacks.append("lattice_attack")
        return attacks

    @staticmethod
    def aes_attacks_order(params: Dict[str, Any]) -> List[str]:
        """Return AES attacks sorted by likelihood."""
        attacks = []
        mode = params.get("mode", "").upper()

        if mode == "ECB":
            attacks.append("ecb_detection")
            attacks.append("ecb_byte_at_a_time")
        elif mode == "CBC":
            attacks.append("padding_oracle")
            attacks.append("cbc_bit_flip")
        elif mode == "GCM":
            attacks.append("gcm_nonce_reuse")
        elif mode == "CTR":
            attacks.append("ctr_reuse")

        return attacks

    @staticmethod
    def should_skip_attack(attack_name: str, params: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Check if an attack should be skipped based on params.

        Returns:
            (should_skip: bool, reason: str)
        """
        n_bits = params.get("n_bits", 0)
        e = params.get("e", 0)

        rules = {
            "trial_division": (
                n_bits > 256,
                f"n is {n_bits} bits, too large for trial division"
            ),
            "fermat": (
                n_bits > 1024,
                f"n is {n_bits} bits, Fermat too slow"
            ),
            "small_e_root": (
                e > 17,
                f"e={e} is not small enough for direct root"
            ),
            "wiener": (
                e < 65537 and n_bits > 0,
                f"e={e} is small, Wiener unlikely to work"
            ),
            "hastad_broadcast": (
                not params.get("multi_ct"),
                "No multiple ciphertexts found"
            ),
            "common_modulus": (
                not params.get("multi_e"),
                "No multiple exponents found"
            ),
            "nonce_reuse": (
                not params.get("nonce_reuse_detected"),
                "No matching r values found"
            ),
        }

        if attack_name in rules:
            skip, reason = rules[attack_name]
            return (skip, reason)

        return (False, "")


# ---------------------------------------------------------------------------
# Convenience
# ---------------------------------------------------------------------------

_extractor = None


def get_param_extractor() -> CryptoParamExtractor:
    """Singleton accessor."""
    global _extractor
    if _extractor is None:
        _extractor = CryptoParamExtractor()
    return _extractor


if __name__ == "__main__":
    # Quick self-test
    sample = '''
n = 0xDEADBEEF
e = 3
c = 123456789012345678901234567890

key = bytes.fromhex("00112233445566778899aabbccddeeff")
iv  = bytes.fromhex("aabbccdd00112233aabbccdd00112233")
from Crypto.Cipher import AES
cipher = AES.new(key, AES.MODE_CBC, iv)
'''
    extractor = CryptoParamExtractor()
    result = extractor.extract_all(sample)

    print("=== Extraction Results ===")
    for section in ["rsa", "ecc", "ecdsa", "aes", "hash", "lattice"]:
        data = result.get(section, {})
        if data:
            print(f"\n[{section.upper()}]")
            for k, v in data.items():
                print(f"  {k} = {v}")

    print(f"\nDetected type: {result['detected_type']}")
    print(f"Hex values: {result['hex_values']}")

    # Test early exit
    checker = EarlyExitChecker()
    if result["rsa"]:
        order = checker.rsa_attacks_order(result["rsa"])
        print(f"\nRSA attack order: {order}")
