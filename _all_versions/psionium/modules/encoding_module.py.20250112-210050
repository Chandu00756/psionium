import base64
import binascii

class EncodingModule:
    def __init__(self, encoding_type="base64"):
        self.encoding_type = encoding_type

    def encode(self, data):
        """
        Encode the input data.
        :param data: Raw data (bytes or string).
        :return: Encoded data (string).
        """
        if isinstance(data, str):
            data = data.encode('utf-8')

        if self.encoding_type == "base64":
            return base64.b64encode(data).decode('utf-8')
        elif self.encoding_type == "hex":
            return binascii.hexlify(data).decode('utf-8')
        else:
            raise ValueError(f"Unsupported encoding type: {self.encoding_type}")

    def decode(self, encoded_data):
        """
        Decode the encoded data.
        :param encoded_data: Encoded data (string).
        :return: Decoded data (bytes).
        """
        if self.encoding_type == "base64":
            return base64.b64decode(encoded_data.encode('utf-8'))
        elif self.encoding_type == "hex":
            return binascii.unhexlify(encoded_data.encode('utf-8'))
        else:
            raise ValueError(f"Unsupported encoding type: {self.encoding_type}")