# Deterministic and unpredictable
#!pip install pycryptodome
import hmac, hashlib, json
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import os

def tweak_from_json_hmac(json_obj, mac_key):
    # canonicalize JSON
    msg = json.dumps(json_obj, sort_keys=True).encode()
    mac = hmac.new(mac_key, msg, hashlib.sha256).digest()   # 32 bytes
    # use HKDF to derive exactly 16 bytes (optional, but explicit)
    hk = HKDF(length=16, algorithm=hashes.SHA256(), salt=None, info=b'xts-tweak')
    tweak16 = hk.derive(mac)
    return tweak16

def tweak_from_json(json_obj, mac_key):
    # canonicalize JSON
    msg = json.dumps(json_obj, sort_keys=True).encode()
    mac = hmac.new(mac_key, msg, hashlib.sha256).digest()   # 32 bytes
    # use HKDF to derive exactly 16 bytes (optional, but explicit)
    hk = HKDF(length=16, algorithm=hashes.SHA256(), salt=None, info=b'xts-tweak')
    tweak16 = hk.derive(mac)
    return tweak16

# mac_key lives in KMS; keep it secret
def derive_tweak_secret(json_obj, mac_key):
    msg = json.dumps(json_obj, sort_keys=True).encode()
    full = hmac.new(mac_key, msg, hashlib.sha256).digest()  # 32B
    return full[:16], full  # 16B tweak, 32B mac for storage

# Non-deterministic, maximally unpredictable
def tweak_from_random():
    return os.urandom(16)

# Non-deterministic, maximally unpredictable
def tweak_from_random_nonce(nonce):
    return os.urandom(16)

# Deterministic but avoid leaking mapping if JSON is public: use nonce + HMAC
def tweak_from_json_hmac_nonce(json_obj, mac_key, nonce):
    # canonicalize JSON
    msg = json.dumps(json_obj, sort_keys=True).encode()
    mac = hmac.new(mac_key, msg + nonce, hashlib.sha256).digest()   # 32 bytes
    # use HKDF to derive exactly 16 bytes (optional, but explicit)
    hk = HKDF(length=16, algorithm=hashes.SHA256(), salt=None, info=b'xts-tweak')
    tweak16 = hk.derive(mac)
    return tweak16

# Use a PRF with secret seed and counter (stream of tweaks)
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

"""
XTS Tweak Derivation Methods
========================================
MAC Key: 94751275a431275ab77fb3fbcc402d82ae92be29a5449ece353703495dd586ae
JSON Object: {'file_id': 'doc_12345', 'sector': 0, 'timestamp': '2024-01-15T10:30:00Z'}

1. Random Tweak (Non-deterministic):
Random tweak: 5875dcacf75d8c486307e14e3ba92ccd (length: 16 bytes)
   → Store this hex value with your ciphertext

2. JSON-based Deterministic Tweak:
JSON-based tweak: 3d66b99353fdc1e519c53665e3febc25 (length: 16 bytes)
   → Same JSON + same key = same tweak

3. JSON-based with Nonce:
JSON+nonce tweak: 5236506be323872630e515447457b257 (length: 16 bytes)
   Nonce: 6234584f9870e9b61232f23709072f16
   → Same JSON + different nonce = different tweak

4. PRF-based Sequential Tweaks:
PRF tweak #0: 7e87fa510ebb6843f15c6bf7a670e813 (length: 16 bytes)
PRF tweak #1: aeecc520494ff8fa3aae183bb6d0f9a9 (length: 16 bytes)
PRF tweak #2: 0ab7473591d36732d77935793ad0b35e (length: 16 bytes)
   Seed: 4a0d96fba44d02d40dc1980cab7739c316007fe864378aa55fd2fd506bbc2cab
   → Deterministic sequence from seed + counter

5. Tweak with MAC Storage:
Tweak portion: 1327025ee0dabbd0bbfe2baf0fd31e54 (length: 16 bytes)
Full MAC: 1327025ee0dabbd0bbfe2baf0fd31e54612324e6eb8e36b6b91b826404c36ebf (length: 32 bytes)
   → Store MAC for verification, use tweak for XTS

6. Verification Example:
   MAC verification: True
   Computed tweak: 1327025ee0dabbd0bbfe2baf0fd31e54

========================================
Summary of stored values for each method:
1. Random:    tweak_hex = '5875dcacf75d8c486307e14e3ba92ccd'
2. JSON:      tweak_hex = '3d66b99353fdc1e519c53665e3febc25'
3. JSON+Nonce: tweak_hex = '5236506be323872630e515447457b257', nonce_hex = '6234584f9870e9b61232f23709072f16'
5. Tweak+MAC: tweak_hex = '1327025ee0dabbd0bbfe2baf0fd31e54', mac_hex = '1327025ee0dabbd0bbfe2baf0fd31e54612324e6eb8e36b6b91b826404c36ebf'
========================================
"""