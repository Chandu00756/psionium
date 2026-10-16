import logging
import os
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'modules'))
from encryption_module import EncryptionModule

class EncryptionSystem:
    def __init__(self):
        self.encryption_module = EncryptionModule()
        self.logger = self._setup_logger()

    def _setup_logger(self):
        """Sets up a logger for audit trails."""
        logger = logging.getLogger("EncryptionSystem")
        logger.setLevel(logging.INFO)
        handler = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        return logger

    def encrypt_data(self, data, algorithm, parameters=None):
        """Encrypts data using the specified algorithm and logs the operation."""
        try:
            encrypted_data = self.encryption_module.encrypt(data, algorithm, parameters)
            self._log_encryption(algorithm, parameters)
            return encrypted_data
        except Exception as e:
            self._log_error(e)
            raise

    def _log_encryption(self, algorithm, parameters):
        """Logs encryption details."""
        self.logger.info(f"Encryption successful: Algorithm={algorithm}, Parameters={parameters}")

    def _log_error(self, error):
        """Logs errors."""
        self.logger.error(f"Encryption failed: {error}")