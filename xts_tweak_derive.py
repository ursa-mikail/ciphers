# Deterministic and unpredictable
#!pip install pycryptodome
import hmac, hashlib, json
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import os

def tweak_from_json_hmac(json_obj, mac_key): # With truncation
    # canonicalize JSON
    msg = json.dumps(json_obj, sort_keys=True).encode()
    mac = hmac.new(mac_key, msg, hashlib.sha256).digest()   # 32 bytes
    # use HKDF to derive exactly 16 bytes (optional, but explicit)
    hk = HKDF(length=16, algorithm=hashes.SHA256(), salt=None, info=b'xts-tweak')
    tweak16 = hk.derive(mac)
    return tweak16

def tweak_from_json(json_obj, mac_key): # With truncation
    # canonicalize JSON
    msg = json.dumps(json_obj, sort_keys=True).encode()
    mac = hmac.new(mac_key, msg, hashlib.sha256).digest()   # 32 bytes
    # use HKDF to derive exactly 16 bytes (optional, but explicit)
    hk = HKDF(length=16, algorithm=hashes.SHA256(), salt=None, info=b'xts-tweak')
    tweak16 = hk.derive(mac)
    return tweak16

# mac_key lives in KMS; keep it secret # With truncation
def derive_tweak_secret(json_obj, mac_key):
    msg = json.dumps(json_obj, sort_keys=True).encode()
    full = hmac.new(mac_key, msg, hashlib.sha256).digest()  # 32B
    return full[:16], full  # 16B tweak, 32B mac for storage    # truncation

# Non-deterministic, maximally unpredictable
def tweak_from_random():
    return os.urandom(16)

# Non-deterministic, maximally unpredictable
def tweak_from_random_nonce(nonce):
    return os.urandom(16)

# Deterministic but avoid leaking mapping if JSON is public: use nonce + HMAC # With truncation
def tweak_from_json_hmac_nonce(json_obj, mac_key, nonce):
    # canonicalize JSON
    msg = json.dumps(json_obj, sort_keys=True).encode()
    mac = hmac.new(mac_key, msg + nonce, hashlib.sha256).digest()   # 32 bytes
    # use HKDF to derive exactly 16 bytes (optional, but explicit)
    hk = HKDF(length=16, algorithm=hashes.SHA256(), salt=None, info=b'xts-tweak')
    tweak16 = hk.derive(mac)
    return tweak16

# Use a PRF with secret seed and counter (stream of tweaks) # No truncation
def tweak_from_prf(seed, counter):
    hk = HKDF(length=16, algorithm=hashes.SHA256(), salt=None, info=b'xts-tweak')
    # Combine seed and counter to create unique input
    input_data = seed + counter.to_bytes(8, 'big')
    tweak16 = hk.derive(input_data)
    return tweak16

# Print hex representation
def print_tweak_hex(tweak, method_name):
    hex_tweak = tweak.hex()
    print(f"{method_name}: {hex_tweak} (length: {len(tweak)} bytes)")
    return hex_tweak


import json, os
from pathlib import Path

# Deterministic mapping + allocated unique sector numbers (zero-collision) 
def load_mapping(domain):
    path = Path(f"{domain}_mapping.json")
    if path.exists():
        return json.loads(path.read_text())
    return {"_counter": 0}

def save_mapping(domain, mapping):
    path = Path(f"{domain}_mapping.json")
    path.write_text(json.dumps(mapping))

def get_or_allocate_tweak(json_obj, domain): # With truncation
    mapping = load_mapping(domain)
    key = json.dumps(json_obj, sort_keys=True)
    if key in mapping:
        return bytes.fromhex(mapping[key])
    counter = mapping["_counter"]
    tweak = counter.to_bytes(16, "little")
    """
    If counter is small (which it will be initially), to_bytes(16, "little") will create a 16-byte array where:
    The least significant bytes contain the counter value

    The remaining bytes are zero-padded
    For example:
    counter = 1 → b'\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    counter = 255 → b'\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    
    # only using the first few bytes effectively, which could be a security concern for XTS mode.
    """
    mapping[key] = tweak.hex()
    mapping["_counter"] = counter + 1
    save_mapping(domain, mapping)
    return tweak


def get_or_allocate_tweak_hash(json_obj, domain):   # With truncation
    mapping = load_mapping(domain)
    key = json.dumps(json_obj, sort_keys=True)
    
    if key in mapping:
        return bytes.fromhex(mapping[key])
    
    # Use hash to get full 16-byte tweak
    tweak = hashlib.sha256(key.encode()).digest()[:16]
    mapping[key] = tweak.hex()
    save_mapping(domain, mapping)
    return tweak

def get_or_allocate_tweak_counter(json_obj, domain):    # With truncation
    mapping = load_mapping(domain)
    key = json.dumps(json_obj, sort_keys=True)
    
    if key in mapping:
        return bytes.fromhex(mapping[key])
    
    counter = mapping["_counter"]
    # Use counter across all bytes
    tweak = b''
    for i in range(16):
        tweak += ((counter >> (8 * i)) & 0xFF).to_bytes(1, 'little')
    
    mapping[key] = tweak.hex()
    mapping["_counter"] = counter + 1
    save_mapping(domain, mapping)
    return tweak


def get_or_allocate_tweak_hmac(json_obj, domain, secret_key=b'your-secret-key'): # No truncation
    mapping = load_mapping(domain)
    key = json.dumps(json_obj, sort_keys=True)
    
    if key in mapping:
        return bytes.fromhex(mapping[key])
    
    # Use HMAC to derive tweak
    h = hmac.new(secret_key, key.encode(), hashlib.sha256)
    tweak = h.digest()[:16]
    
    mapping[key] = tweak.hex()
    save_mapping(domain, mapping)
    return tweak

def demonstrate_usage():
    from cryptography.hazmat.primitives.ciphers import Cipher, modes
    from cryptography.hazmat.primitives.ciphers.algorithms import AES
    from cryptography.hazmat.backends import default_backend
    
    # Your encryption key (should be 32 or 64 bytes for XTS)
    encryption_key = os.urandom(32)
    
    # Example data to encrypt
    data = b"Hello, World! This is a test message."
    json_context = {"file_id": "file123", "sector": 0}
    domain = "myapp"
    
    # Using Option 1 (Hash-based - recommended)
    tweak1 = get_or_allocate_tweak_hash(json_context, domain)
    cipher1 = Cipher(AES(encryption_key), modes.XTS(tweak1), backend=default_backend())
    encryptor1 = cipher1.encryptor()
    encrypted1 = encryptor1.update(data) + encryptor1.finalize()
    
    # Using Option 3 (HMAC-based - most secure)
    tweak3 = get_or_allocate_tweak_hmac(json_context, domain)
    cipher3 = Cipher(AES(encryption_key), modes.XTS(tweak3), backend=default_backend())
    encryptor3 = cipher3.encryptor()
    encrypted3 = encryptor3.update(data) + encryptor3.finalize()
    
    print(f"Original data: {data}")
    print(f"Tweak1 (Hash): {tweak1.hex()}")
    print(f"Tweak3 (HMAC): {tweak3.hex()}")
    print(f"Encrypted1 length: {len(encrypted1)}")
    print(f"Encrypted3 length: {len(encrypted3)}")

# Demo usage
if __name__ == "__main__":
    print("XTS Tweak Derivation Methods\n" + "="*40)
    
    # Generate a MAC key (in practice, this would be from KMS)
    mac_key = os.urandom(32)
    
    # Sample JSON object
    json_obj = {
        "file_id": "doc_12345",
        "sector": 0,
        "timestamp": "2024-01-15T10:30:00Z"
    }

    print(f"MAC Key: {mac_key.hex()}")
    print(f"JSON Object: {json_obj}")
    print()
    
    # Method 1: Random tweak (most common for XTS)
    print("1. Random Tweak (Non-deterministic):")
    random_tweak = tweak_from_random()        # store this hex with ciphertext
    random_hex = print_tweak_hex(random_tweak, "Random tweak")
    print("   → Store this hex value with your ciphertext\n")
    
    # Method 2: JSON-based deterministic tweak
    print("2. JSON-based Deterministic Tweak:")
    json_tweak = tweak_from_json_hmac(json_obj, mac_key)
    json_hex = print_tweak_hex(json_tweak, "JSON-based tweak")
    print("   → Same JSON + same key = same tweak\n")
    
    # Method 3: JSON with nonce (deterministic but hides patterns)
    print("3. JSON-based with Nonce:")
    nonce = os.urandom(16)
    json_nonce_tweak = tweak_from_json_hmac_nonce(json_obj, mac_key, nonce)
    json_nonce_hex = print_tweak_hex(json_nonce_tweak, "JSON+nonce tweak")
    print(f"   Nonce: {nonce.hex()}")
    print("   → Same JSON + different nonce = different tweak\n")
    
    # Method 4: PRF-based sequential tweaks
    print("4. PRF-based Sequential Tweaks:")
    seed = os.urandom(32)
    for i in range(3):
        prf_tweak = tweak_from_prf(seed, i)
        prf_hex = print_tweak_hex(prf_tweak, f"PRF tweak #{i}")
    print(f"   Seed: {seed.hex()}")
    print("   → Deterministic sequence from seed + counter\n")
    
    # Method 5: Tweak + MAC storage (for verification)
    print("5. Tweak with MAC Storage:")
    tweak16, full_mac = derive_tweak_secret(json_obj, mac_key)
    tweak_hex = print_tweak_hex(tweak16, "Tweak portion")
    mac_hex = print_tweak_hex(full_mac, "Full MAC")
    print("   → Store MAC for verification, use tweak for XTS\n")
    
    # Verification example
    print("6. Verification Example:")
    # Recompute to verify
    msg = json.dumps(json_obj, sort_keys=True).encode()
    computed_mac = hmac.new(mac_key, msg, hashlib.sha256).digest()
    matches = hmac.compare_digest(computed_mac, full_mac)
    print(f"   MAC verification: {matches}")
    print(f"   Computed tweak: {computed_mac[:16].hex()}")
    
    print("\n" + "="*40)
    print("Summary of stored values for each method:")
    print(f"1. Random:    tweak_hex = '{random_hex}'")
    print(f"2. JSON:      tweak_hex = '{json_hex}'")
    print(f"3. JSON+Nonce: tweak_hex = '{json_nonce_hex}', nonce_hex = '{nonce.hex()}'")
    print(f"5. Tweak+MAC: tweak_hex = '{tweak_hex}', mac_hex = '{mac_hex}'")
    print("="*40)

    demonstrate_usage()

"""
XTS Tweak Derivation Methods
========================================
MAC Key: f180ee0c4a011866ff2f023eb4e386b3d327d7454ce711c3a5039de7bc2984e4
JSON Object: {'file_id': 'doc_12345', 'sector': 0, 'timestamp': '2024-01-15T10:30:00Z'}

1. Random Tweak (Non-deterministic):
Random tweak: a9ec4ba9458be937de55054c86c10b48 (length: 16 bytes)
   → Store this hex value with your ciphertext

2. JSON-based Deterministic Tweak:
JSON-based tweak: 671fbc0af2d770603204fe207b6b8656 (length: 16 bytes)
   → Same JSON + same key = same tweak

3. JSON-based with Nonce:
JSON+nonce tweak: 9c36c6e6408acae7ea564c752f960f50 (length: 16 bytes)
   Nonce: 40988f19d40ce883ca045aca0b93cf22
   → Same JSON + different nonce = different tweak

4. PRF-based Sequential Tweaks:
PRF tweak #0: 4fcefc96d72d2656ac3c3e89f044dede (length: 16 bytes)
PRF tweak #1: 0273768a1617907c3c49aa0d38e59358 (length: 16 bytes)
PRF tweak #2: 8d7eae7578c89f748aa53d8ad339e9dd (length: 16 bytes)
   Seed: 96af68bca4f4df2cd4111e609c645ef7c03b1b8ac8402fe763650bed53c7e988
   → Deterministic sequence from seed + counter

5. Tweak with MAC Storage:
Tweak portion: 6558926a4408fdbd11d1373ef727616c (length: 16 bytes)
Full MAC: 6558926a4408fdbd11d1373ef727616c2d848d5a10fb148425eb15c1358d4674 (length: 32 bytes)
   → Store MAC for verification, use tweak for XTS

6. Verification Example:
   MAC verification: True
   Computed tweak: 6558926a4408fdbd11d1373ef727616c

========================================
Summary of stored values for each method:
1. Random:    tweak_hex = 'a9ec4ba9458be937de55054c86c10b48'
2. JSON:      tweak_hex = '671fbc0af2d770603204fe207b6b8656'
3. JSON+Nonce: tweak_hex = '9c36c6e6408acae7ea564c752f960f50', nonce_hex = '40988f19d40ce883ca045aca0b93cf22'
5. Tweak+MAC: tweak_hex = '6558926a4408fdbd11d1373ef727616c', mac_hex = '6558926a4408fdbd11d1373ef727616c2d848d5a10fb148425eb15c1358d4674'
========================================
Original data: b'Hello, World! This is a test message.'
Tweak1 (Hash): 5159db2c43b322f2a25346b44f739044
Tweak3 (HMAC): 5159db2c43b322f2a25346b44f739044
Encrypted1 length: 37
Encrypted3 length: 37
"""