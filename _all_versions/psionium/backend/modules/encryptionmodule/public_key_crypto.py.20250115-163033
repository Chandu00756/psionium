from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

def generate_key_pair():
    """
    Generates a public/private key pair.
    Returns:
        private_pem (bytes): Serialized private key in PEM format.
        public_pem (bytes): Serialized public key in PEM format.
    """
    # Generate a private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Generate the corresponding public key
    public_key = private_key.public_key()

    # Serialize the keys
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return private_pem, public_pem

def encrypt_with_public_key(data: bytes, public_key_pem: bytes) -> bytes:
    """
    Encrypts data using the receiver's public key.
    Args:
        data (bytes): Data to encrypt.
        public_key_pem (bytes): Receiver's public key in PEM format.
    Returns:
        encrypted_data (bytes): Encrypted data.
    """
    # Deserialize the public key
    public_key = serialization.load_pem_public_key(public_key_pem)

    # Encrypt the data
    encrypted_data = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    return encrypted_data

def decrypt_with_private_key(encrypted_data: bytes, private_key_pem: bytes) -> bytes:
    """
    Decrypts data using the receiver's private key.
    Args:
        encrypted_data (bytes): Encrypted data.
        private_key_pem (bytes): Receiver's private key in PEM format.
    Returns:
        decrypted_data (bytes): Decrypted data.
    """
    # Deserialize the private key
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None,
    )

    # Decrypt the data
    decrypted_data = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    return decrypted_data