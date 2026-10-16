import os

class FileHandler:
    def __init__(self):
        self.header = "PSIONIUM_v1.0"

    def save_file(self, data, original_path, encoding_type, compression_type, encryption_type):
        """
        Save processed data with a custom extension.
        :param data: Processed data (bytes).
        :param original_path: Path to the original file.
        :param encoding_type: Encoding type (e.g., base64, dynamic).
        :param compression_type: Compression type (e.g., gzip, zlib).
        :param encryption_type: Encryption type (e.g., aes-256).
        :return: Path to the saved file.
        """
        # Create the custom header
        header = f"{self.header}|{encoding_type}|{compression_type}|{encryption_type}"

        # Add the custom extension
        base_name, ext = os.path.splitext(original_path)
        new_ext = f".p{ext[1:]}" if ext else ".psen"
        new_path = base_name + new_ext

        # Write the header and data to the file
        with open(new_path, 'wb') as file:
            file.write(header.encode('utf-8') + b"\n" + data)

        return new_path

    def load_file(self, file_path):
        """
        Load a pSIONIUM file and extract its metadata and data.
        :param file_path: Path to the pSIONIUM file.
        :return: Tuple of (header, encoding_type, compression_type, encryption_type, data).
        """
        with open(file_path, 'rb') as file:
            header_line = file.readline().decode('utf-8').strip()
            data = file.read()

        if not header_line.startswith(self.header):
            raise ValueError("Invalid pSIONIUM file.")

        _, encoding_type, compression_type, encryption_type = header_line.split("|")
        return encoding_type, compression_type, encryption_type, data