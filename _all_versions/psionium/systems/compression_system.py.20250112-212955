from modules.compression_module import CompressionModule

class CompressionSystem:
    def __init__(self, algorithm="gzip"):
        self.compression_module = CompressionModule(algorithm)

    def process(self, data):
        """
        Compress the input data.
        :param data: Raw data (bytes).
        :return: Compressed data (bytes).
        """
        try:
            compressed_data = self.compression_module.compress(data)
            print("Data compressed successfully.")
            return compressed_data
        except Exception as e:
            print(f"Error during compression: {e}")
            raise

    def reverse_process(self, compressed_data):
        """
        Decompress the input data.
        :param compressed_data: Compressed data (bytes).
        :return: Decompressed data (bytes).
        """
        try:
            decompressed_data = self.compression_module.decompress(compressed_data)
            print("Data decompressed successfully.")
            return decompressed_data
        except Exception as e:
            print(f"Error during decompression: {e}")
            raise