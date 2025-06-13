import os, time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

number_of_MB = 80
DATA = os.urandom(1024 * 1024)*number_of_MB  # N MB random data
N = 100

def benchmark(cipher_name, cipher_cls, key_len):
    key = os.urandom(key_len)
    nonce = os.urandom(12)
    cipher = cipher_cls(key)

    # Encrypt
    t0 = time.time()
    for _ in range(N):
        ct = cipher.encrypt(nonce, DATA, None)
    t1 = time.time()

    # Decrypt
    t2 = time.time()
    for _ in range(N):
        pt = cipher.decrypt(nonce, ct, None)
    t3 = time.time()

    time_average_encrypt = (t1 - t0) / N
    time_average_decrypt = (t3 - t2) / N

    print(f"{cipher_name} Encrypt avg: {time_average_encrypt:.6f}s")
    print(f"{cipher_name} Decrypt avg: {time_average_decrypt:.6f}s")

    return time_average_encrypt, time_average_decrypt

# Usage
t_start = time.time()

time_average_encrypt_aes, time_average_decrypt_aes = benchmark("AES-GCM", AESGCM, 32)
time_average_encrypt_chacha, time_average_decrypt_chacha = benchmark("ChaCha20-Poly1305", ChaCha20Poly1305, 32)

time_diff = time_average_encrypt_aes - time_average_encrypt_chacha

if ( time_diff >= 0):
    print("AES-GCM is faster than ChaCha20-Poly1305 ", end ='')
else:
    print("ChaCha20-Poly1305 is faster than AES-GCM ", end ='')

print(f"by : {abs(time_diff):.6f}s")

time_diff = time_average_decrypt_aes - time_average_decrypt_chacha

if ( time_diff >= 0):
    print("AES-GCM is faster than ChaCha20-Poly1305 ", end ='')
else:
    print("ChaCha20-Poly1305 is faster than AES-GCM ", end ='')

print(f"by : {abs(time_diff):.6f}s")

t_end = time.time()

total_time = t_end - t_start
print(f"Total time: {total_time:.6f}s")

"""
AES-GCM Encrypt avg: 0.103866s
AES-GCM Decrypt avg: 0.108257s
ChaCha20-Poly1305 Encrypt avg: 0.136823s
ChaCha20-Poly1305 Decrypt avg: 0.136730s
ChaCha20-Poly1305 is faster than AES-GCM by : 0.032957s
ChaCha20-Poly1305 is faster than AES-GCM by : 0.028473s
Total time: 48.602654s
"""