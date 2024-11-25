""" hmac.py
Generate random data of variable lengths.
Concatenate these random data chunks in random rounds.
Compute the HMAC for each concatenated message using the specified hash functions.
"""

import hmac
import hashlib
import os
import random

def generate_random_bytes(length):
    """Generate random bytes of a given length."""
    return os.urandom(length)

def generate_hmac(key, message, hash_function):
    """Generate HMAC for a given message using the specified hash function."""
    return hmac.new(key, message, hash_function).hexdigest()

# Define the key
key = b'secret_key'

# Define the hash functions to use
hash_functions = {
    'SHA-256': hashlib.sha256,
    'SHA-384': hashlib.sha384,
    'SHA-512': hashlib.sha512
}

# Generate random rounds (between 1 and 10) of data concatenation
rounds = random.randint(1, 10)
print(f'Number of rounds: {rounds}')

# Concatenate random data
message = b''
for i in range(rounds):
    # Generate random length between 1 and 100 bytes
    length = random.randint(1, 100)
    random_data = generate_random_bytes(length)
    message += random_data
    print(f'Round {i+1}: Added {length} bytes.')

# Loop through each hash function and generate the HMAC
for name, hash_function in hash_functions.items():
    hmac_digest = generate_hmac(key, message, hash_function)
    print(f'HMAC-{name}: {hmac_digest}')

"""
Number of rounds: 7
Round 1: Added 17 bytes.
Round 2: Added 25 bytes.
Round 3: Added 48 bytes.
Round 4: Added 6 bytes.
Round 5: Added 46 bytes.
Round 6: Added 51 bytes.
Round 7: Added 81 bytes.
HMAC-SHA-256: 99ae285f4dcc5d990612f2dedd8c933ce49083aec504200a66a24967ef022e00
HMAC-SHA-384: fa7ebebcb362fffbb76113463dfd864c7f2b79ed11d7348e0a5642eef2e75c4be3fe0cd01c5b769d80fc72c65a73b35d
HMAC-SHA-512: aa96252ab857deafdac349d8be2ccaaab00f57939fb4df96d11d4650c92c60a1ea2a3d50605be06c6398a096724fbbb0e74b9c2f92352d1f0b180196802b931e
"""