from systems.encoding_system import EncodingSystem

def test_fallback():
    system = EncodingSystem(encoding_type="dynamic")
    data = "Hello, pSIONIUM!"
    encoded_data = system.process(data)
    decoded_data = system.reverse_process(encoded_data, dimensions=[1, 3, 5])  # Example dimensions
    assert decoded_data.decode('utf-8') == data, "Fallback test failed!"

if __name__ == "__main__":
    test_fallback()
    print("Fallback test passed!")