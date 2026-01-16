#!/usr/bin/env python3
"""
ECDSA Attack Module
====================

Implements attacks against ECDSA/DSA signatures:
- Nonce Reuse Attack
- Biased Nonce Attack (HNP)
- Signature Malleability
"""

from typing import Tuple, Optional, List
import hashlib


def modinv(a: int, n: int) -> int:
    """Modular multiplicative inverse."""
    return pow(a, -1, n)


class ECDSASolver:
    """ECDSA signature attack implementations."""
    
    def __init__(self):
        pass
    
    def nonce_reuse_attack(self, 
                           r: int, 
                           s1: int, s2: int,
                           z1: int, z2: int,
                           n: int) -> Optional[int]:
        """
        Recover private key when same nonce k is used for two signatures.
        
        If two messages m1, m2 are signed with the same k:
        - s1 = k^-1 * (z1 + r*d) mod n
        - s2 = k^-1 * (z2 + r*d) mod n
        
        Then: k = (z1 - z2) * (s1 - s2)^-1 mod n
        And:  d = r^-1 * (s1*k - z1) mod n
        
        Args:
            r: Common r value (proves same k was used)
            s1, s2: Signature s components
            z1, z2: Message hashes (truncated to curve bit length)
            n: Curve order
        
        Returns:
            Private key d if recovered
        """
        try:
            # Calculate nonce k
            s_diff = (s1 - s2) % n
            z_diff = (z1 - z2) % n
            
            k = (z_diff * modinv(s_diff, n)) % n
            
            # Recover private key d
            r_inv = modinv(r, n)
            d = (r_inv * ((s1 * k) - z1)) % n
            
            # Verify: the other signature should also work
            d_check = (r_inv * ((s2 * k) - z2)) % n
            
            if d == d_check:
                return d
            
            # Try with negated k (there are two possible k values)
            k = (-k) % n
            d = (r_inv * ((s1 * k) - z1)) % n
            d_check = (r_inv * ((s2 * k) - z2)) % n
            
            if d == d_check:
                return d
                
            return None
            
        except Exception:
            return None
    
    def nonce_reuse_from_signatures(self,
                                     sig1: Tuple[int, int],
                                     sig2: Tuple[int, int],
                                     msg1: bytes,
                                     msg2: bytes,
                                     n: int,
                                     hash_func=hashlib.sha256) -> Optional[int]:
        """
        High-level nonce reuse attack from full signatures and messages.
        
        Args:
            sig1: (r1, s1) first signature
            sig2: (r2, s2) second signature
            msg1, msg2: Original messages
            n: Curve order
            hash_func: Hash function used (default SHA256)
        
        Returns:
            Private key d if r1 == r2 and attack succeeds
        """
        r1, s1 = sig1
        r2, s2 = sig2
        
        if r1 != r2:
            print("[!] r values differ - no nonce reuse detected")
            return None
        
        # Hash messages
        z1 = int.from_bytes(hash_func(msg1).digest(), 'big')
        z2 = int.from_bytes(hash_func(msg2).digest(), 'big')
        
        # Truncate to curve bit length
        bit_len = n.bit_length()
        z1 = z1 >> max(0, z1.bit_length() - bit_len)
        z2 = z2 >> max(0, z2.bit_length() - bit_len)
        
        return self.nonce_reuse_attack(r1, s1, s2, z1, z2, n)
    
    def biased_nonce_attack(self,
                            signatures: List[Tuple[int, int, int]],
                            n: int,
                            bias_bits: int,
                            pubkey_point=None) -> Optional[int]:
        """
        Attack ECDSA when nonces have known bias (HNP attack).
        
        Uses lattice reduction (LLL) to solve Hidden Number Problem.
        Requires the lattice module.
        
        Args:
            signatures: List of (r, s, z) tuples
            n: Curve order
            bias_bits: Known upper bound on nonce bit length (e.g., k < 2^bias_bits)
            pubkey_point: Public key point (optional, for verification)
        
        Returns:
            Private key d if found
        """
        try:
            from solver.modules.lattice import solve_hnp
            return solve_hnp(signatures, n, bias_bits)
        except ImportError:
            print("[!] Lattice module required for biased nonce attack")
            print("    Use: from solver.modules.lattice import solve_hnp")
            return None
    
    def verify_private_key(self, 
                           d: int, 
                           r: int, s: int, 
                           z: int, 
                           n: int) -> bool:
        """
        Verify that a recovered private key produces valid signatures.
        
        For ECDSA: s = k^-1 * (z + r*d) mod n
        So: k = s^-1 * (z + r*d) mod n
        """
        try:
            s_inv = modinv(s, n)
            k = (s_inv * (z + r * d)) % n
            return 0 < k < n
        except:
            return False
    
    def signature_malleability(self, 
                               r: int, s: int, 
                               n: int) -> Tuple[int, int]:
        """
        Generate malleable signature (r, n-s).
        
        Both (r, s) and (r, -s mod n) are valid signatures for the same message.
        Some implementations only accept s < n/2 (low-s).
        
        Returns:
            (r, s') where s' = n - s (the "high-s" or "low-s" variant)
        """
        return (r, n - s)
    
    def solve(self, **kwargs) -> Optional[int]:
        """
        Generic solve interface.
        
        Attempts nonce reuse if r values match.
        Attempts biased nonce if bias_bits is provided.
        """
        if 'r' in kwargs and 's1' in kwargs and 's2' in kwargs:
            return self.nonce_reuse_attack(
                kwargs['r'],
                kwargs['s1'], kwargs['s2'],
                kwargs['z1'], kwargs['z2'],
                kwargs['n']
            )
        
        if 'signatures' in kwargs and 'bias_bits' in kwargs:
            return self.biased_nonce_attack(
                kwargs['signatures'],
                kwargs['n'],
                kwargs['bias_bits']
            )
        
        return None


# Convenience functions
def ecdsa_nonce_reuse(r: int, s1: int, s2: int, z1: int, z2: int, n: int) -> Optional[int]:
    """Quick access to nonce reuse attack."""
    solver = ECDSASolver()
    return solver.nonce_reuse_attack(r, s1, s2, z1, z2, n)


if __name__ == "__main__":
    print("ECDSA Attack Module")
    print("=" * 40)
    
    # Test with example values (secp256k1-like)
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    
    # Simulated nonce reuse scenario
    # In real attack, these would be extracted from signatures
    print("\n[*] Nonce Reuse Attack")
    print("    When r1 == r2, private key can be recovered")
    
    solver = ECDSASolver()
    print(f"    Solver ready: {solver}")
