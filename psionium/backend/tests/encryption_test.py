import sys
import os
import unittest

sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'modules'))

from encryptionmodule.encryption_module import EncryptionModule

class TestEncryptionModule(unittest.TestCase):
    def setUp(self):
        self.encryption_module = EncryptionModule()
        self.test_data = b"Hello, World! This is a test message."

    def test_supported_algorithms(self):
        algorithms = self.encryption_module.list_supported_algorithms()
        self.assertIsInstance(algorithms, list)
        self.assertTrue(len(algorithms) > 0)
        self.assertIn("Kyber", algorithms)
        self.assertIn("Dilithium", algorithms)
        self.assertIn("Falcon", algorithms)
        self.assertIn("NTRU", algorithms)
        self.assertIn("SPHINCS+", algorithms)
        self.assertIn("AES-256", algorithms)
        self.assertIn("ChaCha20", algorithms)

    def test_kyber_encryption_decryption(self):
        encrypted = self.encryption_module.encrypt(self.test_data, "Kyber")
        decrypted = self.encryption_module.decrypt(encrypted, "Kyber")
        self.assertEqual(self.test_data, decrypted)

    def test_ntru_encryption_decryption(self):
        encrypted = self.encryption_module.encrypt(self.test_data, "NTRU")
        decrypted = self.encryption_module.decrypt(encrypted, "NTRU")
        self.assertEqual(self.test_data, decrypted)

    def test_dilithium_signature(self):
        signed_package = self.encryption_module.encrypt(self.test_data, "Dilithium")
        self.assertIn("signature", signed_package)
        self.assertIn("public_key", signed_package)
        is_valid = self.encryption_module.verify_signature(self.test_data, signed_package["signature"], signed_package["public_key"], "Dilithium")
        self.assertTrue(is_valid)

    def test_falcon_signature(self):
        signed_package = self.encryption_module.encrypt(self.test_data, "Falcon")
        self.assertIn("signature", signed_package)
        self.assertIn("public_key", signed_package)
        is_valid = self.encryption_module.verify_signature(self.test_data, signed_package["signature"], signed_package["public_key"], "Falcon")
        self.assertTrue(is_valid)

    def test_sphincs_signature(self):
        signed_package = self.encryption_module.encrypt(self.test_data, "SPHINCS+")
        self.assertIn("signature", signed_package)
        self.assertIn("public_key", signed_package)
        is_valid = self.encryption_module.verify_signature(self.test_data, signed_package["signature"], signed_package["public_key"], "SPHINCS+")
        self.assertTrue(is_valid)

    def test_aes_encryption_decryption(self):
        key = os.urandom(32)  # 256-bit key
        encrypted = self.encryption_module.encrypt(self.test_data, "AES-256", key)
        decrypted = self.encryption_module.decrypt(encrypted, "AES-256", key)
        self.assertEqual(self.test_data, decrypted)

    def test_chacha20_encryption_decryption(self):
        key = os.urandom(32)  # 256-bit key
        encrypted = self.encryption_module.encrypt(self.test_data, "ChaCha20", key)
        decrypted = self.encryption_module.decrypt(encrypted, "ChaCha20", key)
        self.assertEqual(self.test_data, decrypted)

    def test_unsupported_algorithm(self):
        with self.assertRaises(ValueError):
            self.encryption_module.encrypt(self.test_data, "UnsupportedAlgorithm")

    def test_encryption_failure(self):
        with self.assertRaises(RuntimeError):
            self.encryption_module.encrypt(None, "Kyber")

    def test_decryption_failure(self):
        encrypted = self.encryption_module.encrypt(self.test_data, "Kyber")
        encrypted["ciphertext"] = b"invalid_ciphertext"
        with self.assertRaises(RuntimeError):
            self.encryption_module.decrypt(encrypted, "Kyber")

    def test_signature_verification_failure(self):
        signed_package = self.encryption_module.encrypt(self.test_data, "Dilithium")
        with self.assertRaises(RuntimeError):
            self.encryption_module.verify_signature(b"tampered_data", signed_package["signature"], signed_package["public_key"], "Dilithium")

if __name__ == "__main__":
    unittest.main()
