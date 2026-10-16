from systems.dynamic_encoding_system import DynamicEncodingSystem

def test_dynamic_encoding():
    system = DynamicEncodingSystem()
    data = "Hello, pSIONIUM!"
    encoded_data = system.process(data)
    decoded_data = system.reverse_process(encoded_data, dimensions=[1, 3, 5])  # Example dimensions
    assert decoded_data.decode('utf-8') == data, "Dynamic encoding test failed!"

if __name__ == "__main__":
    test_dynamic_encoding()
    print("Dynamic encoding test passed!")