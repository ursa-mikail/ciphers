# RSA-PSS
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
import os, binascii

def generate_random_bytes(n):
    return os.urandom(n)

def bytes_to_hex(byte_data):
    return binascii.hexlify(byte_data).decode('utf-8')

# Generate RSA private key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

# Get the public key
public_key = private_key.public_key()

# Example usage
N = 16  # Length of random bytes
random_bytes = generate_random_bytes(N)
hex_output = bytes_to_hex(random_bytes)
print(f"message in hex: {hex_output}")

# Message to be signed
# message = b"This is a message to be signed."
message = random_bytes

# Sign the message using RSA-PSS with SHA-256
signature = private_key.sign(
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

# Verify the signature
try:
    public_key.verify(
        signature,
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("Signature is valid.")
except Exception as e:
    print("Signature is invalid:", str(e))

# Optionally, serialize the private key for storage
private_key_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

# Optionally, serialize the public key for storage
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)


directory_out = "./sample_data/out/"
if not os.path.exists(directory_out):
    os.makedirs(directory_out)

# Save the keys to files (optional)
with open(directory_out + "rsa_PSS.private_key.pem", "wb") as f:
    f.write(private_key_pem)

with open(directory_out + "rsa_PSS.public_key.pem", "wb") as f:
    f.write(public_key_pem)

print("Private and public keys saved to 'private_key.pem' and 'public_key.pem'")

"""
message in hex: 1a16cc77490d05ca47b3c5452d80ab00
Signature is valid.
Private and public keys saved to 'private_key.pem' and 'public_key.pem'
"""