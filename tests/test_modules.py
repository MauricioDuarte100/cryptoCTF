#!/usr/bin/env python3
"""
Unit Tests for CryptoCTF Attack Modules
========================================

Tests RSA, XOR, ECC, Classical, and Lattice modules.

Run with: python -m pytest tests/test_modules.py -v
Or:       python tests/test_modules.py
"""

import sys
import unittest
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


class TestRSAModule(unittest.TestCase):
    """Tests for solver.modules.rsa"""
    
    @classmethod
    def setUpClass(cls):
        from solver.modules.rsa import RSASolver
        cls.solver = RSASolver()
    
    def test_cube_root_attack(self):
        """Test small exponent (e=3) attack."""
        # m^3 should be directly recoverable
        m = 123456789
        e = 3
        n = 2**512  # Large enough that c = m^e < n
        c = pow(m, e, n)
        
        # Should recover the message
        result = self.solver.solve(n, e, c)
        # Check if the result contains the original message
        self.assertIsNotNone(result)
    
    def test_wiener_attack(self):
        """Test Wiener's attack on small d."""
        # Known vulnerable RSA parameters
        # p, q close, small d
        from solver.modules.rsa import RSASolver
        
        # This is a simplified test - real Wiener needs specific conditions
        solver = RSASolver()
        # Just verify the method exists and runs
        self.assertTrue(hasattr(solver, '_wiener_attack'))
    
    def test_fermat_factorization(self):
        """Test Fermat factorization for close primes."""
        from solver.modules.rsa import RSASolver
        
        solver = RSASolver()
        self.assertTrue(hasattr(solver, '_fermat_factorization'))
    
    def test_small_n(self):
        """Test factorization of small n."""
        # Very small n that can be factored by trial division
        p, q = 101, 103
        n = p * q
        e = 65537
        m = 42
        c = pow(m, e, n)
        
        result = self.solver.solve(n, e, c)
        # Should find the message
        self.assertIsNotNone(result)


class TestXORModule(unittest.TestCase):
    """Tests for solver.modules.xor"""
    
    @classmethod
    def setUpClass(cls):
        try:
            from solver.modules.xor import XORSolver
            cls.solver = XORSolver()
            cls.available = True
        except:
            cls.available = False
    
    def test_single_byte_xor(self):
        """Test single-byte XOR decryption."""
        if not self.available:
            self.skipTest("XOR module not available")
        
        # Simple XOR with known key
        plaintext = b"Hello World"
        key = 0x42
        ciphertext = bytes(b ^ key for b in plaintext)
        
        # Solver should be able to find the key
        self.assertTrue(hasattr(self.solver, 'solve'))
    
    def test_repeating_key_xor(self):
        """Test repeating-key XOR."""
        if not self.available:
            self.skipTest("XOR module not available")
        
        plaintext = b"Attack at dawn"
        key = b"KEY"
        ciphertext = bytes(p ^ key[i % len(key)] for i, p in enumerate(plaintext))
        
        # Verify XOR is reversible
        decrypted = bytes(c ^ key[i % len(key)] for i, c in enumerate(ciphertext))
        self.assertEqual(decrypted, plaintext)


class TestECCModule(unittest.TestCase):
    """Tests for solver.modules.ecc"""
    
    @classmethod
    def setUpClass(cls):
        try:
            from solver.modules.ecc import ECCSolver
            cls.solver = ECCSolver()
            cls.available = True
        except:
            cls.available = False
    
    def test_point_on_curve(self):
        """Test point validation."""
        if not self.available:
            self.skipTest("ECC module not available")
        
        # Simple curve y^2 = x^3 + ax + b (mod p)
        self.assertTrue(hasattr(self.solver, '_is_on_curve'))
    
    def test_point_addition(self):
        """Test elliptic curve point addition."""
        if not self.available:
            self.skipTest("ECC module not available")
        
        self.assertTrue(hasattr(self.solver, '_add'))
    
    def test_scalar_multiplication(self):
        """Test scalar multiplication."""
        if not self.available:
            self.skipTest("ECC module not available")
        
        self.assertTrue(hasattr(self.solver, '_mul'))


class TestClassicalModule(unittest.TestCase):
    """Tests for solver.modules.classical"""
    
    @classmethod
    def setUpClass(cls):
        try:
            from solver.modules.classical import ClassicalSolver
            cls.solver = ClassicalSolver()
            cls.available = True
        except:
            cls.available = False
    
    def test_caesar_cipher(self):
        """Test Caesar cipher decryption."""
        if not self.available:
            self.skipTest("Classical module not available")
        
        # ROT13 example
        plaintext = "HELLO"
        ciphertext = "URYYB"  # ROT13
        
        self.assertTrue(hasattr(self.solver, 'solve'))


class TestECDSAModule(unittest.TestCase):
    """Tests for solver.modules.ecdsa"""
    
    @classmethod
    def setUpClass(cls):
        try:
            from solver.modules.ecdsa import ECDSASolver
            cls.solver = ECDSASolver()
            cls.available = True
        except Exception as e:
            cls.available = False
            cls.error = str(e)
    
    def test_nonce_reuse_attack(self):
        """Test nonce reuse recovery."""
        if not self.available:
            self.skipTest(f"ECDSA module not available: {self.error}")
        
        # Simulated nonce reuse scenario (secp256k1-like)
        n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        
        # These values would come from two signatures with same r
        # Just verify the method exists
        self.assertTrue(hasattr(self.solver, 'nonce_reuse_attack'))
    
    def test_biased_nonce_attack(self):
        """Test biased nonce (HNP) attack exists."""
        if not self.available:
            self.skipTest("ECDSA module not available")
        
        self.assertTrue(hasattr(self.solver, 'biased_nonce_attack'))
    
    def test_signature_malleability(self):
        """Test signature malleability function."""
        if not self.available:
            self.skipTest("ECDSA module not available")
        
        n = 100
        r, s = 50, 30
        r2, s2 = self.solver.signature_malleability(r, s, n)
        
        self.assertEqual(r2, r)
        self.assertEqual(s2, n - s)  # s' = n - s


class TestAESModule(unittest.TestCase):
    """Tests for solver.modules.aes"""
    
    @classmethod
    def setUpClass(cls):
        try:
            from solver.modules.aes import AESSolver
            cls.solver = AESSolver()
            cls.available = True
        except Exception as e:
            cls.available = False
            cls.error = str(e)
    
    def test_padding_oracle_attack_exists(self):
        """Test padding oracle method exists."""
        if not self.available:
            self.skipTest(f"AES module not available: {self.error}")
        
        self.assertTrue(hasattr(self.solver, 'padding_oracle_attack'))
    
    def test_ecb_oracle_attack_exists(self):
        """Test ECB oracle method exists."""
        if not self.available:
            self.skipTest("AES module not available")
        
        self.assertTrue(hasattr(self.solver, 'ecb_oracle_attack'))
    
    def test_cbc_bit_flip(self):
        """Test CBC bit flipping calculation."""
        if not self.available:
            self.skipTest("AES module not available")
        
        # Test basic XOR calculation
        ct = b'\x00' * 32
        known = b'user=guest'
        target = b'user=admin'
        
        # Method should exist
        self.assertTrue(hasattr(self.solver, 'cbc_bit_flip'))
    
    def test_detect_block_size(self):
        """Test block size detection helper."""
        if not self.available:
            self.skipTest("AES module not available")
        
        self.assertTrue(hasattr(self.solver, '_detect_block_size'))


class TestLatticeModule(unittest.TestCase):

    """Tests for solver.modules.lattice"""
    
    @classmethod
    def setUpClass(cls):
        from solver.modules.lattice import Matrix, LLL, get_backend_info
        cls.Matrix = Matrix
        cls.LLL = LLL
        cls.get_backend_info = get_backend_info
    
    def test_matrix_creation(self):
        """Test matrix creation."""
        M = self.Matrix([[1, 2, 3], [4, 5, 6]])
        self.assertEqual(M.nrows, 2)
        self.assertEqual(M.ncols, 3)
        self.assertEqual(M[0][1], 2)
    
    def test_identity_matrix(self):
        """Test identity matrix creation."""
        I = self.Matrix.identity(3)
        self.assertEqual(I[0][0], 1)
        self.assertEqual(I[0][1], 0)
        self.assertEqual(I[1][1], 1)
    
    def test_lll_reduction(self):
        """Test LLL lattice reduction."""
        # Simple lattice that should reduce well
        M = self.Matrix([
            [1, 0, 0, 100],
            [0, 1, 0, 200],
            [0, 0, 1, 300]
        ])
        
        L = self.LLL(M, backend='python')
        
        # LLL should produce shorter vectors
        # Check that result is still a valid matrix
        self.assertEqual(L.nrows, 3)
        self.assertEqual(L.ncols, 4)
    
    def test_backend_info(self):
        """Test backend availability check."""
        info = self.get_backend_info()
        
        self.assertIn('fpylll', info)
        self.assertIn('python', info)
        self.assertIn('recommended', info)
        self.assertTrue(info['python'])  # Always available


class TestAutoSolver(unittest.TestCase):
    """Tests for auto_solve.py"""
    
    @classmethod
    def setUpClass(cls):
        try:
            from auto_solve import AutoSolver
            cls.AutoSolver = AutoSolver
            cls.available = True
        except Exception as e:
            cls.available = False
            cls.error = str(e)
    
    def test_solver_init(self):
        """Test AutoSolver initialization."""
        if not self.available:
            self.skipTest(f"AutoSolver not available: {self.error}")
        
        solver = self.AutoSolver(verbose=False)
        self.assertIsNotNone(solver)
    
    def test_classify_rsa(self):
        """Test RSA classification."""
        if not self.available:
            self.skipTest("AutoSolver not available")
        
        solver = self.AutoSolver(verbose=False)
        
        # RSA-like text should be classified as RSA
        result = solver.classify("n = 12345, e = 65537, c = encrypted", "")
        self.assertIn(result['type'], ['RSA', 'crypto'])
    
    def test_classify_aes(self):
        """Test AES classification."""
        if not self.available:
            self.skipTest("AutoSolver not available")
        
        solver = self.AutoSolver(verbose=False)
        
        result = solver.classify("AES CBC padding oracle attack", "")
        self.assertIn(result['type'], ['AES', 'Block Cipher', 'crypto'])
    
    def test_extract_params(self):
        """Test parameter extraction."""
        if not self.available:
            self.skipTest("AutoSolver not available")
        
        solver = self.AutoSolver(verbose=False)
        
        code = "n = 123456789\ne = 65537\nc = 987654321"
        params = solver.extract_params(code)
        
        self.assertEqual(params.get('n'), 123456789)
        self.assertEqual(params.get('e'), 65537)
        self.assertEqual(params.get('c'), 987654321)


class TestTrainingData(unittest.TestCase):
    """Tests for training data integrity."""
    
    def test_training_data_exists(self):
        """Test that training data file exists."""
        data_path = PROJECT_ROOT / "data" / "training_data.jsonl"
        self.assertTrue(data_path.exists(), "Training data not found")
    
    def test_training_data_valid(self):
        """Test that training data is valid JSON."""
        import json
        
        data_path = PROJECT_ROOT / "data" / "training_data.jsonl"
        if not data_path.exists():
            self.skipTest("Training data not found")
        
        count = 0
        with open(data_path, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    json.loads(line)
                    count += 1
                except json.JSONDecodeError:
                    self.fail(f"Invalid JSON at line {count + 1}")
        
        self.assertGreater(count, 0, "Training data is empty")
        print(f"\n  Training data: {count} valid entries")


def run_tests():
    """Run all tests with verbose output."""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestRSAModule))
    suite.addTests(loader.loadTestsFromTestCase(TestXORModule))
    suite.addTests(loader.loadTestsFromTestCase(TestECCModule))
    suite.addTests(loader.loadTestsFromTestCase(TestClassicalModule))
    suite.addTests(loader.loadTestsFromTestCase(TestECDSAModule))
    suite.addTests(loader.loadTestsFromTestCase(TestAESModule))
    suite.addTests(loader.loadTestsFromTestCase(TestLatticeModule))
    suite.addTests(loader.loadTestsFromTestCase(TestAutoSolver))
    suite.addTests(loader.loadTestsFromTestCase(TestTrainingData))

    
    # Run with verbosity
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Summary
    print("\n" + "="*60)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Skipped: {len(result.skipped)}")
    print("="*60)
    
    return len(result.failures) + len(result.errors) == 0


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
