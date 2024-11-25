# RSA-OAEP
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

# Generate RSA private key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

# Get the public key
public_key = private_key.public_key()

# Message to be encrypted
random_bytes = generate_random_bytes(N)
# message = b"This is a secret message."
message = random_bytes
hex_output = bytes_to_hex(random_bytes)
print(f"message in hex: {hex_output}")


# Encrypt the message using RSA with OAEP padding
ciphertext = public_key.encrypt(
    message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

#print("Encrypted message:", ciphertext)
print("Encrypted message:", bytes_to_hex(ciphertext))

# Decrypt the message
decrypted_message = private_key.decrypt(
    ciphertext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

#print("Decrypted message:", decrypted_message.decode())
print("Decrypted message:", bytes_to_hex(decrypted_message))


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
with open(directory_out + "rsa_OAEP.private_key.pem", "wb") as f:
    f.write(private_key_pem)

with open(directory_out + "rsa_OAEP.public_key.pem", "wb") as f:
    f.write(public_key_pem)

print("Private and public keys saved to 'private_key.pem' and 'public_key.pem'")

"""
message in hex: cf552f826cc42c0ef0e175837d6b45b0
Encrypted message: 750e0dea9ff54504da54961d45a677b927db0e500d48c8cc3110b0436f91a1f759408b2b08b7a1691761ae773266088d88429d5812117e5198e3e2f44eacf4af5d52a4a9581176dc8c226a3c4927b6518fae947839a6b11c1f4895be72fdd7ba488e59a151487e4f9e6cc2d6c092339542c1b3dde3a7d4837abffcc1398cd049036b1fe3b7bdd90de5edbfb2bfb689a1b5aab9e7511f3ce0e94dbfc4dcb3f2a331f5daa983d52a5eb0cc1ff73521da75b24365d54bfad69f0cf8f20830cfd19d7e56f219396c2217e20f0b73c69ed1af860216ec0b9aacc204c7f1334621ba9f1b58329bbf14e9cf0cc96725d3c8bea1ad5815bc3579ba483980c55dd26f4bcd
Decrypted message: cf552f826cc42c0ef0e175837d6b45b0
Private and public keys saved to 'private_key.pem' and 'public_key.pem'
"""