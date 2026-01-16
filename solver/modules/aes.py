#!/usr/bin/env python3
"""
AES Attack Module
==================

Implements attacks against AES encryption modes:
- Padding Oracle Attack (CBC)
- ECB Oracle Attack (byte-at-a-time)
- CBC Bit Flipping Attack
- GCM Nonce Reuse (Forbidden Attack)
"""

from typing import Callable, Optional, List, Tuple
import os


class AESSolver:
    """AES mode-specific attack implementations."""
    
    BLOCK_SIZE = 16  # AES block size in bytes
    
    def __init__(self):
        pass
    
    # =========================================================================
    # PADDING ORACLE ATTACK (CBC)
    # =========================================================================
    
    def padding_oracle_attack(self,
                              oracle: Callable[[bytes], bool],
                              ciphertext: bytes,
                              iv: bytes = None,
                              block_size: int = 16,
                              verbose: bool = True) -> bytes:
        """
        Decrypt ciphertext using a padding oracle.
        
        The oracle function should return True if padding is valid, False otherwise.
        
        Args:
            oracle: Function that takes ciphertext and returns True/False for padding validity
            ciphertext: The ciphertext to decrypt (may include IV as first block)
            iv: Initialization vector (if not prepended to ciphertext)
            block_size: Cipher block size (16 for AES)
            verbose: Print progress
        
        Returns:
            Decrypted plaintext (with padding)
        """
        if iv is not None:
            ciphertext = iv + ciphertext
        
        # Split into blocks
        blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]
        
        if len(blocks) < 2:
            raise ValueError("Need at least 2 blocks (IV + ciphertext)")
        
        plaintext = b""
        
        # Decrypt each block (except first which is IV)
        for block_idx in range(1, len(blocks)):
            if verbose:
                print(f"[*] Decrypting block {block_idx}/{len(blocks)-1}")
            
            prev_block = bytearray(blocks[block_idx - 1])
            curr_block = blocks[block_idx]
            
            # Intermediate state after block cipher decryption
            intermediate = bytearray(block_size)
            
            # Recover each byte from end to start
            for byte_pos in range(block_size - 1, -1, -1):
                padding_value = block_size - byte_pos
                
                # Prepare the crafted previous block
                crafted = bytearray(block_size)
                
                # Set already-known bytes to produce correct padding
                for i in range(byte_pos + 1, block_size):
                    crafted[i] = intermediate[i] ^ padding_value
                
                # Brute force the current byte
                found = False
                for guess in range(256):
                    crafted[byte_pos] = guess
                    
                    # Build test ciphertext
                    test_ct = bytes(crafted) + curr_block
                    
                    if oracle(test_ct):
                        # Verify it's not a false positive (for last byte)
                        if byte_pos == block_size - 1 and padding_value == 1:
                            # Flip second-to-last byte to verify
                            verify_crafted = bytearray(crafted)
                            verify_crafted[byte_pos - 1] ^= 1
                            if not oracle(bytes(verify_crafted) + curr_block):
                                continue
                        
                        intermediate[byte_pos] = guess ^ padding_value
                        found = True
                        break
                
                if not found:
                    print(f"[!] Failed at byte {byte_pos}")
                    intermediate[byte_pos] = 0
            
            # Recover plaintext: P = I XOR C_prev
            block_plaintext = bytes(intermediate[i] ^ prev_block[i] for i in range(block_size))
            plaintext += block_plaintext
        
        return plaintext
    
    # =========================================================================
    # ECB ORACLE ATTACK (Byte-at-a-time)
    # =========================================================================
    
    def ecb_oracle_attack(self,
                          oracle: Callable[[bytes], bytes],
                          block_size: int = 16,
                          max_secret_len: int = 256,
                          verbose: bool = True) -> bytes:
        """
        Recover secret appended by ECB oracle (byte-at-a-time attack).
        
        The oracle encrypts: user_input || secret
        We recover 'secret' by controlling user_input.
        
        Args:
            oracle: Function that takes plaintext and returns ciphertext
            block_size: Cipher block size (detect if unknown)
            max_secret_len: Maximum length of secret to recover
            verbose: Print progress
        
        Returns:
            Recovered secret bytes
        """
        # Detect block size if needed
        if block_size == 0:
            block_size = self._detect_block_size(oracle)
            if verbose:
                print(f"[*] Detected block size: {block_size}")
        
        # Verify ECB mode (identical blocks)
        test = oracle(b"A" * block_size * 3)
        if test[0:block_size] != test[block_size:block_size*2]:
            print("[!] Warning: May not be ECB mode")
        
        secret = b""
        
        for i in range(max_secret_len):
            # Padding to push one unknown byte to block boundary
            padding_len = block_size - 1 - (len(secret) % block_size)
            padding = b"A" * padding_len
            
            # Get target block (contains padding + known secret + 1 unknown byte)
            target_block_idx = (len(secret) + padding_len) // block_size
            target = oracle(padding)
            target_block = target[target_block_idx * block_size:(target_block_idx + 1) * block_size]
            
            # Brute force the unknown byte
            found = False
            for byte_val in range(256):
                # Build guess: padding + known_secret + guess_byte
                guess = padding + secret + bytes([byte_val])
                ct = oracle(guess)
                guess_block = ct[target_block_idx * block_size:(target_block_idx + 1) * block_size]
                
                if guess_block == target_block:
                    secret += bytes([byte_val])
                    found = True
                    if verbose and len(secret) % 16 == 0:
                        print(f"[*] Recovered {len(secret)} bytes...")
                    break
            
            if not found:
                # Likely hit padding or end of secret
                break
        
        if verbose:
            print(f"[+] Recovered {len(secret)} bytes total")
        
        return secret
    
    def _detect_block_size(self, oracle: Callable[[bytes], bytes]) -> int:
        """Detect cipher block size by finding when output length jumps."""
        base_len = len(oracle(b""))
        for i in range(1, 64):
            new_len = len(oracle(b"A" * i))
            if new_len > base_len:
                return new_len - base_len
        return 16  # Default AES
    
    # =========================================================================
    # CBC BIT FLIPPING ATTACK
    # =========================================================================
    
    def cbc_bit_flip(self,
                     ciphertext: bytes,
                     known_plaintext: bytes,
                     target_plaintext: bytes,
                     position: int,
                     block_size: int = 16) -> bytes:
        """
        Modify ciphertext to change specific plaintext bytes (CBC mode).
        
        Flipping bit at position i in block N changes the same bit at
        position i in the PLAINTEXT of block N+1.
        
        WARNING: This corrupts block N's plaintext.
        
        Args:
            ciphertext: Original ciphertext (may include IV)
            known_plaintext: Known plaintext at target position
            target_plaintext: Desired plaintext at target position
            position: Byte position in the full plaintext to modify
            block_size: Cipher block size
        
        Returns:
            Modified ciphertext
        """
        ct = bytearray(ciphertext)
        
        # Calculate which block contains the target byte
        target_block = position // block_size
        byte_in_block = position % block_size
        
        # We modify the PREVIOUS block's ciphertext
        modify_pos = (target_block - 1) * block_size + byte_in_block
        
        if modify_pos < 0:
            raise ValueError("Cannot modify first block - need to modify IV")
        
        if len(known_plaintext) != len(target_plaintext):
            raise ValueError("Known and target plaintext must be same length")
        
        # Apply XOR mask
        for i, (known, target) in enumerate(zip(known_plaintext, target_plaintext)):
            if modify_pos + i < len(ct):
                ct[modify_pos + i] ^= known ^ target
        
        return bytes(ct)
    
    def cbc_flip_single_byte(self,
                              ciphertext: bytes,
                              block_num: int,
                              byte_pos: int,
                              old_val: int,
                              new_val: int,
                              block_size: int = 16) -> bytes:
        """
        Flip a single byte in CBC plaintext.
        
        Args:
            ciphertext: Full ciphertext including IV
            block_num: Target plaintext block number (0 = first real block, after IV)
            byte_pos: Byte position within the block (0-15)
            old_val: Current byte value at that position
            new_val: Desired byte value
            block_size: Block size (16 for AES)
        
        Returns:
            Modified ciphertext
        """
        ct = bytearray(ciphertext)
        
        # Modify the previous ciphertext block (or IV for block 0)
        modify_idx = block_num * block_size + byte_pos
        
        ct[modify_idx] ^= old_val ^ new_val
        
        return bytes(ct)
    
    # =========================================================================
    # GCM FORBIDDEN ATTACK (Nonce Reuse)
    # =========================================================================
    
    def gcm_forbidden_attack(self,
                              ct1: bytes, tag1: bytes, aad1: bytes,
                              ct2: bytes, tag2: bytes, aad2: bytes,
                              nonce: bytes) -> Optional[bytes]:
        """
        Recover GCM authentication key H when nonce is reused.
        
        When the same nonce is used for two different messages,
        the auth key H can be recovered by solving polynomial equations.
        
        Args:
            ct1, tag1, aad1: First ciphertext, tag, and additional authenticated data
            ct2, tag2, aad2: Second message components
            nonce: The reused nonce
        
        Returns:
            Authentication key H (16 bytes) if recovered
        
        Note: This is a simplified interface. Full implementation requires
        Galois field arithmetic over GF(2^128).
        """
        # This attack requires polynomial arithmetic in GF(2^128)
        # Full implementation would use libraries like pycryptodome
        print("[!] GCM Forbidden Attack requires GF(2^128) polynomial arithmetic")
        print("[*] The attack works by:")
        print("    1. XOR the two authentication equations (T1 ⊕ T2)")
        print("    2. This eliminates E_k(J0), leaving only GHASH terms")
        print("    3. Solve the polynomial equation for H in GF(2^128)")
        print("    4. Once H is known, can forge valid tags for any message")
        
        # Check if we have the required components
        if tag1 == tag2:
            print("[!] Tags are identical - messages may be identical")
            return None
        
        return None  # Full implementation needs GF(2^128) library
    
    def solve(self, attack_type: str, **kwargs):
        """
        Generic solve interface.
        
        Args:
            attack_type: One of 'padding_oracle', 'ecb_oracle', 'cbc_flip', 'gcm_forbidden'
            **kwargs: Attack-specific parameters
        """
        if attack_type == 'padding_oracle':
            return self.padding_oracle_attack(
                kwargs['oracle'],
                kwargs['ciphertext'],
                kwargs.get('iv'),
                kwargs.get('block_size', 16)
            )
        
        elif attack_type == 'ecb_oracle':
            return self.ecb_oracle_attack(
                kwargs['oracle'],
                kwargs.get('block_size', 16)
            )
        
        elif attack_type == 'cbc_flip':
            return self.cbc_flip_single_byte(
                kwargs['ciphertext'],
                kwargs['block_num'],
                kwargs['byte_pos'],
                kwargs['old_val'],
                kwargs['new_val']
            )
        
        return None


# Convenience functions
def padding_oracle(oracle, ciphertext, iv=None):
    """Quick padding oracle attack."""
    solver = AESSolver()
    return solver.padding_oracle_attack(oracle, ciphertext, iv)


def ecb_oracle(oracle):
    """Quick ECB oracle attack."""
    solver = AESSolver()
    return solver.ecb_oracle_attack(oracle)


if __name__ == "__main__":
    print("AES Attack Module")
    print("=" * 40)
    print("\nAvailable attacks:")
    print("  - padding_oracle_attack(oracle, ciphertext, iv)")
    print("  - ecb_oracle_attack(oracle)")
    print("  - cbc_bit_flip(ciphertext, known, target, position)")
    print("  - gcm_forbidden_attack(ct1, tag1, aad1, ct2, tag2, aad2, nonce)")
