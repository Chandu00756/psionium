from modules.dynamic_encoding_module import DynamicEncodingModule

class DynamicEncodingSystem:
    def __init__(self):
        self.encoding_module = DynamicEncodingModule()

    def process(self, data):
        """
        Process the input data by encoding it dynamically.
        :param data: Raw data (bytes or string).
        :return: Encoded data (string), dimensions (list).
        """
        try:
            encoded_data = self.encoding_module.encode(data)
            print(f"Data encoded dynamically: {encoded_data}")
            return encoded_data
        except Exception as e:
            print(f"Error during dynamic encoding: {e}")
            raise

    def reverse_process(self, encoded_data, dimensions):
        """
        Reverse the dynamic encoding process.
        :param encoded_data: Encoded data (string).
        :param dimensions: Selected dimensions (list).
        :return: Decoded data (bytes).
        """
        try:
            decoded_data = self.encoding_module.decode(encoded_data, dimensions)
            print(f"Data decoded dynamically: {decoded_data.decode('utf-8')}")
            return decoded_data
        except Exception as e:
            print(f"Error during dynamic decoding: {e}")
            raise