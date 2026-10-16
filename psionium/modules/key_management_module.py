import os

class KeyManagementModule:
    def __init__(self):
        """
        Initialize the key management module.
        """
        self.keys = {}

    def generate_key(self, key_id):
        """
        Generate a new encryption key.
        :param key_id: Unique identifier for the key.
        :return: Encryption key (bytes).
        """
        key = os.urandom(32)  # 256-bit key
        self.keys[key_id] = key
        return key

    def get_key(self, key_id):
        """
        Retrieve an encryption key.
        :param key_id: Unique identifier for the key.
        :return: Encryption key (bytes).
        """
        if key_id not in self.keys:
            raise ValueError(f"Key not found: {key_id}")
        return self.keys[key_id]

    def delete_key(self, key_id):
        """
        Delete an encryption key.
        :param key_id: Unique identifier for the key.
        """
        if key_id in self.keys:
            del self.keys[key_id]