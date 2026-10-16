import hashlib

class ScreenerModule:
    def __init__(self):
        """
        Initialize the screener module.
        """
        pass

    def validate(self, original_data, processed_data):
        """
        Validate if the processed data matches the original data.
        :param original_data: Original data (bytes).
        :param processed_data: Processed data (bytes).
        :return: True if valid, False otherwise.
        """
        original_hash = hashlib.sha256(original_data).hexdigest()
        processed_hash = hashlib.sha256(processed_data).hexdigest()
        return original_hash == processed_hash
    