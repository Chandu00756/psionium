from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

class EncryptionModule:
    def __init__(self, algorithm="aes-256", key=None):
        """
        Initialize the encryption module.
        :param algorithm: Encryption algorithm (default: aes-256).
        :param key: Encryption key (bytes). If None, a random key is generated.
        """
        self.algorithm = algorithm
        self.key = key if key else os.urandom(32)  # 256-bit key for AES-256
        self.iv = os.urandom(16)  # Initialization vector

    def encrypt(self, data):
        """
        Encrypt the input data.
        :param data: Raw data (bytes).
        :return: Encrypted data (bytes).
        """
        if self.algorithm == "aes-256":
            cipher = Cipher(
                algorithms.AES(self.key),
                modes.CFB(self.iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            return self.iv + encryptor.update(data) + encryptor.finalize()
        else:
            raise ValueError(f"Unsupported encryption algorithm: {self.algorithm}")

    def decrypt(self, encrypted_data):
        """
        Decrypt the input data.
        :param encrypted_data: Encrypted data (bytes).
        :return: Decrypted data (bytes).
        """
        if self.algorithm == "aes-256":
            iv = encrypted_data[:16]  # Extract IV from the beginning
            cipher = Cipher(
                algorithms.AES(self.key),
                modes.CFB(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            return decryptor.update(encrypted_data[16:]) + decryptor.finalize()
        else:
            raise ValueError(f"Unsupported encryption algorithm: {self.algorithm}")