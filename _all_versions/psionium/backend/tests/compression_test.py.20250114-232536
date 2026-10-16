# backend/tests/compression_test.py
import os
import sys
import time

# Add the backend directory to the Python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from systems.compression.compression_system import CompressionSystem

def get_file_size_in_bytes(file_path: str) -> int:
    """Get the size of a file in bytes."""
    return os.path.getsize(file_path)

def get_file_size_in_bits(file_path: str) -> int:
    """Get the size of a file in bits."""
    return get_file_size_in_bytes(file_path) * 8

def calculate_compression_ratio(original_size: int, compressed_size: int) -> float:
    """Calculate the compression ratio."""
    return original_size / compressed_size if compressed_size > 0 else 0

def test_various_file_types():
    downloads_path = os.path.join(os.path.expanduser('~'), 'Downloads')
    test_files = [
        'sample.txt',
        'image.jpg',
        'document.pdf',
        'audio.mp3',
        'video.mp4'
    ]

    compression_system = CompressionSystem()

    for file_name in test_files:
        file_path = os.path.join(downloads_path, file_name)
        if not os.path.exists(file_path):
            print(f"File not found: {file_path}")
            continue

        print(f"\nTesting file: {file_name}")

        # Read the original file
        with open(file_path, "rb") as file:
            original_data = file.read()

        # Get original file size in bytes and bits
        original_size_bytes = len(original_data)
        original_size_bits = original_size_bytes * 8
        print(f"Original size: {original_size_bytes} bytes ({original_size_bits} bits)")

        # Compress the file
        start_time = time.time()
        compressed_data = compression_system.compress_data(original_data, save_path=f"{file_path}.compressed")
        compression_time = time.time() - start_time

        # Get compressed file size in bytes and bits
        compressed_size_bytes = len(compressed_data)
        compressed_size_bits = compressed_size_bytes * 8
        print(f"Compressed size: {compressed_size_bytes} bytes ({compressed_size_bits} bits)")

        # Calculate compression ratio
        compression_ratio = calculate_compression_ratio(original_size_bytes, compressed_size_bytes)
        print(f"Compression ratio: {compression_ratio:.2f}")

        # Log compression time
        print(f"Compression time: {compression_time:.4f} seconds")

        # Decompress the file
        start_time = time.time()
        decompressed_data = compression_system.decompress_data(compressed_data)
        decompression_time = time.time() - start_time

        # Log decompression time
        print(f"Decompression time: {decompression_time:.4f} seconds")

        # Verify integrity
        if original_data == decompressed_data:
            print("Integrity check: PASSED")
        else:
            print("Integrity check: FAILED")

        # Save compressed file for reference
        compressed_file_path = f"{file_path}.compressed"
        with open(compressed_file_path, "wb") as file:
            file.write(compressed_data)
        print(f"Compressed file saved to: {compressed_file_path}")

if __name__ == "__main__":
    test_various_file_types()