import gzip
import zlib

class DecompressionModule:
    def __init__(self, algorithm="gzip"):
        """
        Initialize the decompression module.
        :param algorithm: Decompression algorithm (default: gzip).
        """
        self.algorithm = algorithm

    def decompress(self, compressed_data):
        """
        Decompress the input data.
        :param compressed_data: Compressed data (bytes).
        :return: Decompressed data (bytes).
        """
        if self.algorithm == "gzip":
            return gzip.decompress(compressed_data)
        elif self.algorithm == "zlib":
            return zlib.decompress(compressed_data)
        else:
            raise ValueError(f"Unsupported decompression algorithm: {self.algorithm}")