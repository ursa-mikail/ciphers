""" sign_message_with_all_keys.py
✅ Reads each private key from keys/personal/<key_type>/private_key.pem
✅ Signs a message (e.g., "hello world")
✅ Outputs the signature in signature_out/<key_type>/signature.bin
✅ Creates signature_out/ and subfolders automatically

signature_out/
├── rsa/
│   └── signature.bin
├── dsa/
│   └── signature.bin
├── ecdsa/
│   └── signature.bin
└── ed25519/
    └── signature.bin

"""
import os
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec, ed25519
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils

def load_private_key(key_path: Path):
    with key_path.open("rb") as f:
        return crypto_serialization.load_pem_private_key(
            f.read(),
            password=None,
        )

def sign_with_key(key_type: str, private_key, message: bytes) -> bytes:
    if key_type == "rsa":
        return private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    elif key_type == "dsa":
        return private_key.sign(
            message,
            hashes.SHA256()
        )
    elif key_type == "ecdsa":
        return private_key.sign(
            message,
            ec.ECDSA(hashes.SHA256())
        )
    elif key_type == "ed25519":
        return private_key.sign(message)
    else:
        raise ValueError(f"Unsupported key type: {key_type}")

def main():
    base_dir = Path("keys/personal")
    output_dir = Path("signature_out")
    message = b"hello world"

    key_types = ["rsa", "dsa", "ecdsa", "ed25519"]

    for key_type in key_types:
        priv_path = base_dir / key_type / "private_key.pem"
        if not priv_path.exists():
            print(f"[!] Skipping {key_type}: private key not found.")
            continue

        try:
            print(f"[+] Signing with {key_type.upper()} key...")
            private_key = load_private_key(priv_path)
            signature = sign_with_key(key_type, private_key, message)

            # Output directory
            out_dir = output_dir / key_type
            out_dir.mkdir(parents=True, exist_ok=True)

            # Save signature
            sig_path = out_dir / "signature.bin"
            sig_path.write_bytes(signature)
            print(f"[✓] Signature saved to {sig_path}\n")

        except Exception as e:
            print(f"[!] Error signing with {key_type}: {e}\n")

if __name__ == "__main__":
    main()

"""
[+] Signing with RSA key...
[✓] Signature saved to signature_out/rsa/signature.bin

[+] Signing with DSA key...
[✓] Signature saved to signature_out/dsa/signature.bin

[+] Signing with ECDSA key...
[✓] Signature saved to signature_out/ecdsa/signature.bin

[+] Signing with ED25519 key...
[✓] Signature saved to signature_out/ed25519/signature.bin

"""