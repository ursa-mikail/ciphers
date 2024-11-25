# AES-XTS.py
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

def generate_key():
    return os.urandom(64)  # AES-XTS requires a 512-bit key (two 256-bit keys)

def xts_encrypt(key, data, tweak):
    if len(tweak) != 16:
        raise ValueError("tweak must be 128-bits (16 bytes) for xts")

    cipher = Cipher(algorithms.AES(key), modes.XTS(tweak), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()

def xts_decrypt(key, data, tweak):
    if len(tweak) != 16:
        raise ValueError("tweak must be 128-bits (16 bytes) for xts")

    cipher = Cipher(algorithms.AES(key), modes.XTS(tweak), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(data) + decryptor.finalize()

def main():
    key = generate_key()
    tweak = os.urandom(16)  # Tweak must be 128 bits (16 bytes)

    #data = b"This is the data to encrypt using AES XTS mode."
    N = 100
    data = generate_random_bytes(N)
    hex_output = bytes_to_hex(data)
    print(f"message in hex: {hex_output}")
    #print(f"Original Data: {data}")

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    encrypted_data = xts_encrypt(key, padded_data, tweak)
    print(f"Encrypted Data: {encrypted_data}")
    #print(f"Encrypted Data: {encrypted_data}")
    print(f"Encrypted Data: {bytes_to_hex(encrypted_data)}")

    decrypted_data = xts_decrypt(key, encrypted_data, tweak)
    #print(f"Decrypted Data: {decrypted_data}")
    print(f"Decrypted Data: {bytes_to_hex(decrypted_data)}")
    unpadder = padding.PKCS7(128).unpadder()
    unpadded_data = unpadder.update(decrypted_data) + unpadder.finalize()

    #print(f"Decrypted Data: {unpadded_data}")
    print(f"Decrypted Data (unpadded_data): {bytes_to_hex(unpadded_data)}")

if __name__ == "__main__":
    main()

"""
message in hex: 3b1fdc22b5941c5f15c6af509cbd5ba3d6daa3ff81ecceaeb85c97d2d7e3d5fe9d4eabb8012f53c50a543091fe0446d5014c99ed2a00e54ea1f5168565bad3f7a5a3f4b175e1f0b542f2d6e7326ce577c187c0c3d0f64e3107a1925b1dc3ce0788276029
Encrypted Data: b"5\x89\x8a\xc2$K\xff\xaeaC=\xa7\xf4y\xcb\x0e\x8fc\xb5\x85\xa4m\x85\\\xebB8\xe6\x97hsB\xf4\x92\xcc\xca\x07\xbbC-(\xf8\x1e(\xd3\xabiq\xf3'7c9\xc1\xefj\x02\t?-\x02M\xfa\xd9\xf1\x0f\xae5\xef\xb3\x9epr\x8a$ZQ\x13\xb1\xb2\x03\xbe\xdb\x82cV\xb7\xda\xcd\x8d\x89*\xe16\xbc\x9a\xe8\xf5Ls\x1bZ\xf7\x91\xc3\xa9\x17\xde6\xd7Wg"
Encrypted Data: 35898ac2244bffae61433da7f479cb0e8f63b585a46d855ceb4238e697687342f492ccca07bb432d28f81e28d3ab6971f327376339c1ef6a02093f2d024dfad9f10fae35efb39e70728a245a5113b1b203bedb826356b7dacd8d892ae136bc9ae8f54c731b5af791c3a917de36d75767
Decrypted Data: 3b1fdc22b5941c5f15c6af509cbd5ba3d6daa3ff81ecceaeb85c97d2d7e3d5fe9d4eabb8012f53c50a543091fe0446d5014c99ed2a00e54ea1f5168565bad3f7a5a3f4b175e1f0b542f2d6e7326ce577c187c0c3d0f64e3107a1925b1dc3ce07882760290c0c0c0c0c0c0c0c0c0c0c0c
Decrypted Data (unpadded_data): 3b1fdc22b5941c5f15c6af509cbd5ba3d6daa3ff81ecceaeb85c97d2d7e3d5fe9d4eabb8012f53c50a543091fe0446d5014c99ed2a00e54ea1f5168565bad3f7a5a3f4b175e1f0b542f2d6e7326ce577c187c0c3d0f64e3107a1925b1dc3ce0788276029
"""