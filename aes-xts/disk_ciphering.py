"""
Key splitting: In XTS, a 64-byte key means two 32-byte AES-256 keys
Tweak purpose: The tweak is typically derived from a sector number in disk encryption
Data length: XTS requires the plaintext to be at least 16 bytes (one block)

Caveat(s):
Proper tweak handling: The tweak is passed during cipher creation, not during encryption/decryption calls
"""

#!pip install pycryptodome
import os
from math import ceil
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BLOCK_SIZE = 16  # AES block size in bytes

def generate_random_bytes(n: int) -> bytes:
    """Generate N random bytes."""
    return os.urandom(n)


def aes_xts_encrypt(key: bytes, plaintext: bytes, tweak: bytes) -> bytes:
    """Encrypt plaintext using AES-XTS mode."""
    if len(key) not in (32, 64):
        raise ValueError("Key must be 32 bytes (AES-128-XTS) or 64 bytes (AES-256-XTS)")
    if len(tweak) != 16:
        raise ValueError(f"Tweak must be exactly 16 bytes, got {len(tweak)}")
    
    # For XTS mode, the key is split into two equal halves
    cipher = Cipher(algorithms.AES(key), modes.XTS(tweak))
    encryptor = cipher.encryptor()
    
    # XTS handles the encryption in blocks automatically
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext


def aes_xts_decrypt(key: bytes, ciphertext: bytes, tweak: bytes) -> bytes:
    """Decrypt ciphertext using AES-XTS mode."""
    if len(tweak) != 16:
        raise ValueError(f"Tweak must be exactly 16 bytes, got {len(tweak)}")

    cipher = Cipher(algorithms.AES(key), modes.XTS(tweak))
    decryptor = cipher.decryptor()
    
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext


def main():
    N = 100_000  # number of random bytes to encrypt
    data = generate_random_bytes(N)
    key = os.urandom(64)  # AES-256-XTS (512 bits = 2×256-bit keys)
    tweak = os.urandom(16)  # 16-byte tweak (typically sector number)

    print(f"Encrypting {len(data)} bytes...\n")
    print(f"Key length: {len(key)} bytes")
    print(f"Tweak length: {len(tweak)} bytes")

    ciphertext = aes_xts_encrypt(key, data, tweak)
    decrypted = aes_xts_decrypt(key, ciphertext, tweak)

    print("=== AES-XTS Encryption Stats ===")
    print(f"Total bytes:         {len(data)}")
    print(f"Block size:          {BLOCK_SIZE} bytes")
    print(f"Total blocks:        {ceil(len(data) / BLOCK_SIZE)}")
    print(f"Last block size:     {len(data) % BLOCK_SIZE or BLOCK_SIZE} bytes")
    print(f"Ciphertext length:   {len(ciphertext)} bytes")
    print(f"Decryption matches:  {decrypted == data}")
    print(f"Tweak:               {tweak.hex()}")
    print(f"Key length:          {len(key)} bytes")


if __name__ == "__main__":
    main()

"""
Encrypting 100000 bytes...

Key length: 64 bytes
Tweak length: 16 bytes
=== AES-XTS Encryption Stats ===
Total bytes:         100000
Block size:          16 bytes
Total blocks:        6250
Last block size:     16 bytes
Ciphertext length:   100000 bytes
Decryption matches:  True
Tweak:               d06156c09b760690a97662dc34ed72c7
Key length:          64 bytes
"""    
