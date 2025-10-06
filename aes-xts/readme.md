# AES-XTS Encryption Toolkit
An implementation of AES-XTS (XEX-based Tweaked CodeBook mode with CipherText Stealing) for disk and file encryption with SHA256 integrity verification.

## 📖 Overview
AES-XTS is the standard encryption mode for disk encryption systems, providing efficient sector-based encryption with unique tweaks per sector. This implementation includes both file encryption capabilities and disk encryption simulation with proper sector handling.

## 🚀 Features

### Core Encryption

- AES-XTS-128 and AES-XTS-256 support
- Sector-based encryption simulating disk encryption
- Cryptographically secure random number generation
- Proper tweak handling derived from sector numbers

### File Operations

- Complete file encryption/decryption
- Random file generation for testing
- Configurable sector sizes (512B, 4KB, etc.)
- Memory-efficient chunk processing

### Integrity Verification

- SHA256 hashing before and after encryption
- Automatic integrity verification
- File size validation
- Comprehensive audit logging

### Security

- Cryptographic randomness using os.urandom()
- Secure key management
- Progress indicators for large files
- Error handling and validation

## Manual Key Management
```python
# Generate specific key size
from xts_encryptor import generate_key, save_key, load_key

# AES-128-XTS (32 bytes) or AES-256-XTS (64 bytes)
key = generate_key(64)  # AES-256-XTS
save_key(key, 'my_encryption_key.key')

# Load key for decryption
loaded_key = load_key('my_encryption_key.key')
encryptor = XTSFileEncryptor(loaded_key)
```

## Custom Sector Sizes
```python
# Simulate different storage devices
encryptor.encrypt_file('file.bin', 'file.bin.encrypted', sector_size=512)   # Traditional HDD
encryptor.encrypt_file('file.bin', 'file.bin.encrypted', sector_size=4096)  # Modern SSD
encryptor.encrypt_file('file.bin', 'file.bin.encrypted', sector_size=16384) # Advanced format
```

## 🏗 Architecture

### XTS Mode Fundamentals
``` text
AES-XTS Encryption Process:
1. Key Splitting: 64-byte key → Two 32-byte AES-256 keys
2. Tweak Generation: Sector number → 16-byte tweak
3. Per-Sector Encryption: Each sector encrypted independently
4. CipherText Stealing: Handles partial blocks efficiently
```
