# AES-GCM-SIV
import requests
import os
import re
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV

def download_test_vectors(url, filepath):
    response = requests.get(url)
    response.raise_for_status()
    with open(filepath, 'w') as file:
        file.write(response.text)

def convert_key_to_bits(key, bits):
    key_bytes = bytes.fromhex(key)
    if bits == 128:
        return key_bytes[:16]
    elif bits == 192:
        if len(key_bytes) == 16:
            return key_bytes + b'\x00' * 8
        return key_bytes[:24]
    elif bits == 256:
        if len(key_bytes) == 16:
            return key_bytes + b'\x00' * 16
        if len(key_bytes) == 24:
            return key_bytes + b'\x00' * 8
        return key_bytes
    else:
        raise ValueError("Unsupported key length")

def encrypt(key, iv, plaintext, aad, key_bits):
    key_bytes = convert_key_to_bits(key, key_bits)
    aesgcm = AESGCMSIV(key_bytes)

    nonce = bytes.fromhex(iv)
    plain_text_bytes = bytes.fromhex(plaintext)
    aad_bytes = bytes.fromhex(aad)

    ciphertext = aesgcm.encrypt(nonce, plain_text_bytes, aad_bytes)
    tag = ciphertext[-16:]  # The last 16 bytes are the tag
    cipher = ciphertext[:-16]

    return cipher.hex(), tag.hex()

def build_vectors(filename, key_bits):
    with open(filename, 'r') as file:
        lines = file.readlines()

    count = 0
    result = []
    key, iv, aad, plaintext = "", "", "", ""

    for line in lines:
        line = line.strip()
        if line.startswith("Key"):
            if count != 0:
                ciphertext, tag = encrypt(key, iv, plaintext, aad, key_bits)
                result.append(f"Tag = {tag}\nCiphertext = {ciphertext}\n")
            result.append(f"\nCOUNT = {count}")
            count += 1
            key = re.search(r"Key = (.*)", line).group(1)
            result.append(f"Key = {convert_key_to_bits(key, key_bits).hex()}")
        elif line.startswith("IV"):
            iv = re.search(r"IV = (.*)", line).group(1)
            result.append(f"IV = {iv}")
        elif line.startswith("AAD"):
            aad = re.search(r"AAD = (.*)", line).group(1)
            result.append(f"AAD = {aad}")
        elif line.startswith("Plaintext"):
            plaintext = re.search(r"Plaintext = (.*)", line).group(1)
            result.append(f"Plaintext = {plaintext}")

    ciphertext, tag = encrypt(key, iv, plaintext, aad, key_bits)
    result.append(f"Tag = {tag}\nCiphertext = {ciphertext}\n")
    return "\n".join(result)

def write_file(data, filename):
    with open(filename, 'w') as file:
        file.write(data)

def main():
    url = "https://raw.githubusercontent.com/openssl/openssl/a2b1ab6100d5f0fb50b61d241471eea087415632/test/recipes/30-test_evp_data/evpciph_aes_gcm_siv.txt"
    path = "./sample_data/evpciph_aes_gcm_siv.txt"
    os.makedirs(os.path.dirname(path), exist_ok=True)
    download_test_vectors(url, path)

    directory_out = "./sample_data/vectors"
    if not os.path.exists(directory_out):
        os.makedirs(directory_out)

    for bits, filename in [(128, "aes-128-gcm-siv.txt"), (192, "aes-192-gcm-siv.txt"), (256, "aes-256-gcm-siv.txt")]:
        result = build_vectors(path, bits)
        write_file(result, os.path.join(directory_out, filename))

if __name__ == "__main__":
    main()


"""
outputs:
    ./sample_data/vectors/
    aes-128-gcm-siv.txt
    aes-192-gcm-siv.txt
    aes-256-gcm-siv.txt
"""