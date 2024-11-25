# AES-XEX
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

def generate_key():
    return os.urandom(32)  # AES-256 key

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def aes_encrypt(key, plaintext):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()

def aes_decrypt(key, ciphertext):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

def xex_encrypt(key, data, tweak):
    block_size = algorithms.AES.block_size // 8
    if len(data) % block_size != 0:
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        data = padder.update(data) + padder.finalize()

    encrypted_data = b''
    for i in range(0, len(data), block_size):
        block = data[i:i + block_size]
        tweak_block = aes_encrypt(key, tweak)
        xored_block = xor_bytes(block, tweak_block)
        encrypted_block = aes_encrypt(key, xored_block)
        final_block = xor_bytes(encrypted_block, tweak_block)
        encrypted_data += final_block
        tweak = aes_encrypt(key, tweak)  # Update tweak

    return encrypted_data

def xex_decrypt(key, data, tweak):
    block_size = algorithms.AES.block_size // 8

    decrypted_data = b''
    for i in range(0, len(data), block_size):
        block = data[i:i + block_size]
        tweak_block = aes_encrypt(key, tweak)
        xored_block = xor_bytes(block, tweak_block)
        decrypted_block = aes_decrypt(key, xored_block)
        final_block = xor_bytes(decrypted_block, tweak_block)
        decrypted_data += final_block
        tweak = aes_encrypt(key, tweak)  # Update tweak

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_data = unpadder.update(decrypted_data) + unpadder.finalize()

    return decrypted_data

def main():
    key = generate_key()
    tweak = os.urandom(16)  # Initial tweak value

    #data = b"This is the data to encrypt using AES XEX mode."
    #print(f"Original Data: {data}")

    N = 100
    data = generate_random_bytes(N)
    hex_output = bytes_to_hex(data)
    print(f"message in hex: {hex_output}")
    #print(f"Original Data: {data}")

    encrypted_data = xex_encrypt(key, data, tweak)
    #print(f"Encrypted Data: {encrypted_data}")
    print(f"Encrypted Data: {bytes_to_hex(encrypted_data)}")

    decrypted_data = xex_decrypt(key, encrypted_data, tweak)
    #print(f"Decrypted Data: {decrypted_data}")
    print(f"Decrypted Data: {bytes_to_hex(decrypted_data)}")

if __name__ == "__main__":
    main()

"""
message in hex: cb91f06803e8de1df70ce6688d2c793f74328def47c563e4afda80630a0ba66541c88319176e42d2d02a8da5278aa1d0d6f439e6441c36172055d11890c48c3793e20bca511fe86f674caed85f98bbf2556ba292501c7df5a17dda269f818677720d99a2
Encrypted Data: 2a77fcf9d256423a7c3eecc1b385a5ce307c624b99ae230bbbbf8e6b91557462051d243a9f510a5f090196dd74d191b898f1a473362d7536b928e625f90b2d6aabcbf69ea4484cd3badd6a4e6028fa03c39f82fb9e620ce432d91ab98858abab57d52041c5e7797fedf515a188f3a9be
Decrypted Data: cb91f06803e8de1df70ce6688d2c793f74328def47c563e4afda80630a0ba66541c88319176e42d2d02a8da5278aa1d0d6f439e6441c36172055d11890c48c3793e20bca511fe86f674caed85f98bbf2556ba292501c7df5a17dda269f818677720d99a2
"""