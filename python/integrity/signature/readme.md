# SSH Key Manager and Signer

This Python project generates SSH keys for different algorithms, organizes them in directories, and signs a sample message using each key.

---

## Features

- Generate key pairs for:
  - RSA (2048 bits)
  - DSA (1024 bits, deprecated)
  - ECDSA (curve SECP256R1)
  - Ed25519

- Save private and public keys in PEM format under:

```
.
├── keys/
│ └── personal/
│ ├── rsa/
│ │ ├── private_key.pem
│ │ └── public_key.pem
│ ├── dsa/
│ ├── ecdsa/
│ └── ed25519/
├── signature_out/
│ ├── rsa/
│ │ └── signature.bin
│ ├── dsa/
│ ├── ecdsa/
│ └── ed25519/
├── generate_and_derive_keys.py
└── sign_message_all_keys.py
```