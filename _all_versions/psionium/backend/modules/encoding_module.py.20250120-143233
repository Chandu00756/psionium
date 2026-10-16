import base64

class EncodingModule:
    def __init__(self, encoding_type="base64"):
        self.encoding_type = encoding_type

    def encode(self, data):
        """
        Encode data using the specified encoding type.
        :param data: Raw data (bytes or string).
        :return: Encoded data (bytes).
        """
        if isinstance(data, str):
            data = data.encode('utf-8')

        if self.encoding_type == "base64":
            return base64.b64encode(data)
        elif self.encoding_type == "hex":
            return data.hex().encode('utf-8')
        else:
            raise ValueError(f"Unsupported encoding type: {self.encoding_type}")

    def decode(self, encoded_data):
        """
        Decode data using the specified encoding type.
        :param encoded_data: Encoded data (bytes).
        :return: Decoded data (bytes).
        """
        if self.encoding_type == "base64":
            return base64.b64decode(encoded_data)
        elif self.encoding_type == "hex":
            return bytes.fromhex(encoded_data.decode('utf-8'))
        else:
            raise ValueError(f"Unsupported encoding type: {self.encoding_type}")