#!pip install pycryptodome
#!pip install pynacl
# nonce length requirement is managed correctly for XChaCha20_Poly1305 (24 bytes).

import binascii
from nacl.secret import SecretBox
from nacl.utils import random
import random as random_gen

def generate_random_int (bound_upper, bound_lower):
  random_integer = random_gen.randint(bound_lower, bound_upper)
  return random_integer

def generate_random_hex(number_of_bytes):
    return binascii.hexlify(os.urandom(number_of_bytes)).decode()  

def generate_poly1305(context_hex, secret_key, num_bytes):
    """Generate Poly1305 MAC from context using secret key and return specified number of bytes."""
    context_bytes = hex_to_bytes(context_hex)

    # Poly1305 key must be 32 bytes
    if len(secret_key) != 32:
        raise ValueError("Secret key must be 32 bytes long")

    # Create a SecretBox for Poly1305 MAC generation
    box = SecretBox(secret_key.encode())

    # Generate a MAC (Note: SecretBox.encrypt expects a nonce; for simplicity, we'll use a random nonce)
    nonce = random(SecretBox.NONCE_SIZE)
    encrypted = box.encrypt(context_bytes, nonce)

    # The MAC is the last 16 bytes of the encrypted message
    poly1305_mac = encrypted[-SecretBox.MACBYTES:]

    # Return the specified number of bytes
    return poly1305_mac[:num_bytes]

# Example usage
number_of_bytes = generate_random_int (bound_upper=100, bound_lower=1)
context_hex = generate_random_hex(number_of_bytes) # "4a656665"  # Example hex string
secret_key = generate_random_hex(number_of_bytes = 32) # "this_is_32_byte_secret_key!"  # Example key (must be 32 bytes)
num_bytes = 16

# Make sure your secret_key is exactly 32 bytes
secret_key = secret_key.ljust(32)[:32]

mac_poly1305 = generate_poly1305(context_hex, secret_key, num_bytes).hex()

print(f"context_hex: {context_hex}")
print(f"mac_poly1305: {mac_poly1305}")


"""
context_hex: eb36393a6765d025578cc126a76a957f82642e0a5ec1018edb4173918acb5222
mac_poly1305: 39164883ad2872d68bc1c99ce6180714
"""