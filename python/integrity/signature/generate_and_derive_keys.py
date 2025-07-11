""" generate_and_derive_keys.py
✅ Generate keys for each type: RSA, Ed25519, ECDSA, DSA
✅ Write the private key to private_key.pem
✅ Read back that private key file
✅ Derive and re-save the public key as public_key.pem

keys/
└── personal/
    ├── rsa/
    │   ├── private_key.pem
    │   └── public_key.pem
    ├── ed25519/
    ├── ecdsa/
    └── dsa/
"""

import base64
from pathlib import Path
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, ed25519
from cryptography.hazmat.primitives import serialization as crypto_serialization

def extract_base64_from_pem(pem_bytes: bytes) -> str:
    lines = pem_bytes.decode().splitlines()
    return ''.join(line for line in lines if not line.startswith("-----"))

def write_private_key(private_key, key_path: Path):
    pem_bytes = private_key.private_bytes(
        encoding=crypto_serialization.Encoding.PEM,
        format=crypto_serialization.PrivateFormat.PKCS8,
        encryption_algorithm=crypto_serialization.NoEncryption()
    )
    key_path.write_bytes(pem_bytes)
    print(f"[+] Private key saved to {key_path}")
    print(f"[*] Base64 (truncated): {extract_base64_from_pem(pem_bytes)[:60]}...\n")

def derive_and_write_public_key_from_private(pem_path: Path, pub_path: Path):
    pem_data = pem_path.read_bytes()
    private_key = crypto_serialization.load_pem_private_key(
        pem_data,
        password=None,
        backend=crypto_default_backend()
    )
    public_key = private_key.public_key()
    pub_bytes = public_key.public_bytes(
        encoding=crypto_serialization.Encoding.PEM,
        format=crypto_serialization.PublicFormat.SubjectPublicKeyInfo
    )
    pub_path.write_bytes(pub_bytes)
    print(f"[+] Derived public key saved to {pub_path}\n")

def generate_and_derive(key_type: str, keygen_func, base_path: Path):
    key_dir = base_path / key_type
    key_dir.mkdir(parents=True, exist_ok=True)

    print(f"[=== {key_type.upper()} ===]")
    private_key = keygen_func()

    priv_path = key_dir / "private_key.pem"
    pub_path = key_dir / "public_key.pem"

    write_private_key(private_key, priv_path)
    derive_and_write_public_key_from_private(priv_path, pub_path)

def main():
    base_path = Path("keys/personal")

    key_types = {
        "rsa": lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=crypto_default_backend()),
        "dsa": lambda: dsa.generate_private_key(key_size=1024, backend=crypto_default_backend()),
        "ecdsa": lambda: ec.generate_private_key(ec.SECP256R1(), backend=crypto_default_backend()),
        "ed25519": lambda: ed25519.Ed25519PrivateKey.generate()
    }

    for key_type, keygen_func in key_types.items():
        try:
            generate_and_derive(key_type, keygen_func, base_path)
        except Exception as e:
            print(f"[!] Failed for {key_type}: {e}\n")

if __name__ == "__main__":
    main()

"""
[=== RSA ===]
[+] Private key saved to keys/personal/rsa/private_key.pem
[*] Base64 (truncated): MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDXiHfnWnJp...

[+] Derived public key saved to keys/personal/rsa/public_key.pem

[=== DSA ===]
[+] Private key saved to keys/personal/dsa/private_key.pem
[*] Base64 (truncated): MIIBSwIBADCCASsGByqGSM44BAEwggEeAoGBAJ5BEXo2L2lLYrLThKdn7T7f...

[+] Derived public key saved to keys/personal/dsa/public_key.pem

[=== ECDSA ===]
[+] Private key saved to keys/personal/ecdsa/private_key.pem
[*] Base64 (truncated): MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgoMO0jao+Vh3r...

[+] Derived public key saved to keys/personal/ecdsa/public_key.pem

[=== ED25519 ===]
[+] Private key saved to keys/personal/ed25519/private_key.pem
[*] Base64 (truncated): MC4CAQAwBQYDK2VwBCIEIP/IwcvQfbI3+m9ixDVq03Gee0aXYwVhGssYp+hI...

[+] Derived public key saved to keys/personal/ed25519/public_key.pem

"""