from oqs import KeyEncapsulation
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import base64

# Message to be encrypted
message = "Hello world!"

# Step 1: Key Encapsulation using Kyber
kemalg = "Kyber768"

with KeyEncapsulation(kemalg) as client:
    # Client generates keypair
    public_key = client.generate_keypair()

    # Server (could be another party) encapsulates secret with client's public key
    with KeyEncapsulation(kemalg) as server:
        ciphertext, shared_secret_server = server.encap_secret(public_key)

    # Client decapsulates to get the same shared secret
    shared_secret_client = client.decap_secret(ciphertext)

    # The shared secret is now the same for both client and server and will be used as the encryption key
    assert shared_secret_client == shared_secret_server, "Shared secrets do not match!"

# Step 2: Encrypt the message using AES-GCM with the shared secret
iv = os.urandom(12)
cipher = Cipher(algorithms.AES(shared_secret_client), modes.GCM(iv), backend=None)
encryptor = cipher.encryptor()
ciphertext = encryptor.update(message.encode()) + encryptor.finalize()

# The tag ensures the integrity of the message
tag = encryptor.tag

# Combine the IV, ciphertext, and tag into a single encrypted package
encrypted_message = base64.b64encode(iv + ciphertext + tag)

print(f"Encrypted message: {encrypted_message.decode()}")

# Step 3: Decryption process (using the shared secret derived from Kyber)
# Decrypt the message
decryptor = Cipher(algorithms.AES(shared_secret_server), modes.GCM(iv, tag), backend=None).decryptor()
decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()

print(f"Decrypted message: {decrypted_message.decode()}")

# Verify that the decrypted message matches the original
assert decrypted_message.decode() == message, "Decrypted message does not match original!"
print("Encryption and decryption successful!")
