from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class DecryptionModule:
    def __init__(self, algorithm="aes-256", key=None):
        """
        Initialize the decryption module.
        :param algorithm: Decryption algorithm (default: aes-256).
        :param key: Decryption key (bytes). Must match the encryption key.
        """
        self.algorithm = algorithm
        self.key = key
        if not self.key:
            raise ValueError("Decryption key is required.")

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
            raise ValueError(f"Unsupported decryption algorithm: {self.algorithm}")