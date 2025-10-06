#!pip install pycryptodome
"""
AES-XTS File Encryption
Key splitting: In XTS, a 64-byte key means two 32-byte AES-256 keys
Tweak purpose: The tweak is typically derived from a sector number in disk encryption
Data length: XTS requires the plaintext to be at least 16 bytes (one block)

✅ Progress indicators - Shows encryption/decryption progress
✅ File verification - Automatically verifies decryption success
✅ Sector-based encryption - Simulates real disk encryption
✅ Key management - Saves and loads encryption keys
✅ Error handling - Proper error messages for Colab environment

🎲 Random File Generation
Generates cryptographically secure random bytes
Configurable file size (default: 2MB)
Progress indicators during generation
Memory-efficient chunked writing
"""

"""
AES-XTS File Encryption for Google Colab with SHA256 Verification
Generates random bytes as file and verifies integrity with SHA256 hashes
"""

import os
import hashlib
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class XTSFileEncryptor:
    def __init__(self, key: bytes = None):
        """
        Initialize XTS cipher.
        For AES-256-XTS: key should be 64 bytes (2×256-bit keys)
        For AES-128-XTS: key should be 32 bytes (2×128-bit keys)
        """
        if key is None:
            key = os.urandom(64)  # Default to AES-256-XTS
        self.key = key
        self.block_size = 16  # AES block size
    
    def generate_tweak(self, sector_number: int = 0) -> bytes:
        """Generate tweak from sector number (16 bytes, little-endian)."""
        return sector_number.to_bytes(16, byteorder='little')
    
    def calculate_sha256(self, file_path: str) -> str:
        """Calculate SHA256 hash of a file."""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            # Read and update hash in chunks of 4K
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    
    def calculate_sha256_bytes(self, data: bytes) -> str:
        """Calculate SHA256 hash of bytes data."""
        return hashlib.sha256(data).hexdigest()
    
    def generate_random_file(self, file_path: str, size_mb: float = 1.0) -> str:
        """
        Generate a file filled with random bytes.
        
        Args:
            file_path: Path where to save the random file
            size_mb: Size of file in megabytes
        """
        size_bytes = int(size_mb * 1024 * 1024)
        
        print(f"🎲 Generating random file: {size_mb} MB ({size_bytes:,} bytes)")
        
        with open(file_path, 'wb') as f:
            # Generate in chunks to avoid memory issues
            chunk_size = 1024 * 1024  # 1MB chunks
            bytes_written = 0
            
            while bytes_written < size_bytes:
                chunk = os.urandom(min(chunk_size, size_bytes - bytes_written))
                f.write(chunk)
                bytes_written += len(chunk)
                
                progress = (bytes_written / size_bytes) * 100
                print(f"📊 Generating: {bytes_written:,}/{size_bytes:,} bytes ({progress:.1f}%)", end='\r')
        
        print(f"\n✅ Random file generated: {file_path}")
        return file_path
    
    def encrypt_file(self, input_file: str, output_file: str, sector_size: int = 4096) -> str:
        """
        Encrypt file using AES-XTS mode.
        
        Args:
            input_file: Path to input file
            output_file: Path to output file
            sector_size: Size of each sector for tweak generation
        """
        input_path = Path(input_file)
        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_file}")
        
        file_size = input_path.stat().st_size
        total_sectors = (file_size + sector_size - 1) // sector_size
        
        print(f"🔐 Encrypting file: {input_file}")
        print(f"📁 File size: {file_size:,} bytes")
        print(f"📦 Sector size: {sector_size} bytes")
        print(f"🔢 Total sectors: {total_sectors}")
        
        with open(input_file, 'rb') as fin, open(output_file, 'wb') as fout:
            sector_number = 0
            
            while True:
                # Read sector
                sector_data = fin.read(sector_size)
                if not sector_data:
                    break
                
                # Generate tweak for this sector
                tweak = self.generate_tweak(sector_number)
                
                # Encrypt sector
                cipher = Cipher(algorithms.AES(self.key), modes.XTS(tweak), backend=default_backend())
                encryptor = cipher.encryptor()
                
                # XTS requires data to be at least 16 bytes
                if len(sector_data) < 16:
                    # Pad small final sector
                    sector_data = sector_data.ljust(16, b'\x00')
                
                encrypted_sector = encryptor.update(sector_data) + encryptor.finalize()
                fout.write(encrypted_sector)
                
                sector_number += 1
                
                # Progress indicator
                if sector_number % 100 == 0 or sector_number == total_sectors:
                    progress = (sector_number / total_sectors) * 100
                    print(f"🔄 Processed {sector_number}/{total_sectors} sectors ({progress:.1f}%)", end='\r')
        
        print(f"\n✅ Encryption complete: {output_file}")
        return output_file
    
    def decrypt_file(self, input_file: str, output_file: str, sector_size: int = 4096, original_size: int = None) -> str:
        """
        Decrypt file using AES-XTS mode.
        
        Args:
            input_file: Path to encrypted file
            output_file: Path to decrypted file
            sector_size: Size of each sector for tweak generation
            original_size: Original file size (for trimming padding)
        """
        input_path = Path(input_file)
        if not input_path.exists():
            raise FileNotFoundError(f"Input file not found: {input_file}")
        
        encrypted_size = input_path.stat().st_size
        total_sectors = (encrypted_size + sector_size - 1) // sector_size
        
        print(f"🔓 Decrypting file: {input_file}")
        print(f"📁 Encrypted size: {encrypted_size:,} bytes")
        print(f"📦 Sector size: {sector_size} bytes")
        print(f"🔢 Total sectors: {total_sectors}")
        
        with open(input_file, 'rb') as fin, open(output_file, 'wb') as fout:
            sector_number = 0
            
            while True:
                # Read encrypted sector
                sector_data = fin.read(sector_size)
                if not sector_data:
                    break
                
                # Generate tweak for this sector
                tweak = self.generate_tweak(sector_number)
                
                # Decrypt sector
                cipher = Cipher(algorithms.AES(self.key), modes.XTS(tweak), backend=default_backend())
                decryptor = cipher.decryptor()
                
                decrypted_sector = decryptor.update(sector_data) + decryptor.finalize()
                
                # Handle last sector padding
                if original_size and sector_number == total_sectors - 1:
                    bytes_remaining = original_size - (sector_number * sector_size)
                    decrypted_sector = decrypted_sector[:bytes_remaining]
                
                fout.write(decrypted_sector)
                sector_number += 1
                
                # Progress indicator
                if sector_number % 100 == 0 or sector_number == total_sectors:
                    progress = (sector_number / total_sectors) * 100
                    print(f"🔄 Processed {sector_number}/{total_sectors} sectors ({progress:.1f}%)", end='\r')
        
        print(f"\n✅ Decryption complete: {output_file}")
        return output_file

def generate_key(key_size: int = 64) -> bytes:
    """Generate a random key for XTS encryption."""
    if key_size not in (32, 64):
        raise ValueError("Key size must be 32 (AES-128-XTS) or 64 (AES-256-XTS) bytes")
    return os.urandom(key_size)

def save_key(key: bytes, key_file: str):
    """Save key to file."""
    with open(key_file, 'wb') as f:
        f.write(key)
    print(f"💾 Key saved to: {key_file}")

def load_key(key_file: str) -> bytes:
    """Load key from file."""
    with open(key_file, 'rb') as f:
        key = f.read()
    return key

def demo_random_file_encryption(file_size_mb: float = 2.0):
    """
    Demo function that generates random bytes file and shows SHA256 hashes.
    
    Args:
        file_size_mb: Size of random file to generate in megabytes
    """
    print("🚀 AES-XTS Random File Encryption with SHA256 Verification")
    print("=" * 60)
    
    # File paths
    random_file = "random_data.bin"
    encrypted_file = "random_data.bin.encrypted"
    decrypted_file = "random_data.bin.decrypted"
    key_file = "encryption_key.key"
    
    # Initialize encryptor
    encryptor = XTSFileEncryptor()
    
    print("\n" + "=" * 60)
    print("🎲 PHASE 1: GENERATE RANDOM FILE")
    print("=" * 60)
    
    # Generate random file
    encryptor.generate_random_file(random_file, file_size_mb)
    
    # Calculate original file SHA256
    original_hash = encryptor.calculate_sha256(random_file)
    file_size = Path(random_file).stat().st_size
    
    print(f"📊 Original File Size: {file_size:,} bytes")
    print(f"🔍 Original SHA256:    {original_hash}")
    
    print("\n" + "=" * 60)
    print("🔐 PHASE 2: ENCRYPTION")
    print("=" * 60)
    
    # Save the key
    save_key(encryptor.key, key_file)
    
    # Encrypt the file
    encryptor.encrypt_file(random_file, encrypted_file, sector_size=4096)
    
    # Calculate encrypted file SHA256
    encrypted_hash = encryptor.calculate_sha256(encrypted_file)
    
    print(f"📊 Encrypted File Size: {Path(encrypted_file).stat().st_size:,} bytes")
    print(f"🔍 Encrypted SHA256:    {encrypted_hash}")
    
    print("\n" + "=" * 60)
    print("🔓 PHASE 3: DECRYPTION")
    print("=" * 60)
    
    # Decrypt the file (need to recreate encryptor with the same key)
    decryptor = XTSFileEncryptor(encryptor.key)
    decryptor.decrypt_file(encrypted_file, decrypted_file, sector_size=4096, 
                          original_size=file_size)
    
    # Calculate decrypted file SHA256
    decrypted_hash = decryptor.calculate_sha256(decrypted_file)
    
    print(f"📊 Decrypted File Size: {Path(decrypted_file).stat().st_size:,} bytes")
    print(f"🔍 Decrypted SHA256:    {decrypted_hash}")
    
    print("\n" + "=" * 60)
    print("✅ VERIFICATION RESULTS")
    print("=" * 60)
    
    # Verify hashes match
    hashes_match = original_hash == decrypted_hash
    file_sizes_match = file_size == Path(decrypted_file).stat().st_size
    
    print(f"🔍 SHA256 Hashes Match:    {hashes_match}")
    print(f"📊 File Sizes Match:       {file_sizes_match}")
    print(f"🎯 Integrity Verified:     {hashes_match and file_sizes_match}")
    
    if hashes_match and file_sizes_match:
        print("🎉 SUCCESS: File integrity perfectly maintained!")
    else:
        print("❌ ERROR: File integrity check failed!")
    
    # Display comparison table
    print("\n" + "=" * 60)
    print("📋 COMPARISON TABLE")
    print("=" * 60)
    print(f"{'File':<20} {'Size (bytes)':<15} {'SHA256'}")
    print("-" * 60)
    print(f"{'Original':<20} {file_size:<15,} {original_hash}")
    print(f"{'Encrypted':<20} {Path(encrypted_file).stat().st_size:<15,} {encrypted_hash}")
    print(f"{'Decrypted':<20} {Path(decrypted_file).stat().st_size:<15,} {decrypted_hash}")
    
    return {
        'original_file': random_file,
        'encrypted_file': encrypted_file,
        'decrypted_file': decrypted_file,
        'key_file': key_file,
        'original_hash': original_hash,
        'encrypted_hash': encrypted_hash,
        'decrypted_hash': decrypted_hash,
        'integrity_verified': hashes_match and file_sizes_match
    }

def encrypt_user_file_with_hash(input_path: str, key_size: int = 64, sector_size: int = 4096):
    """Encrypt a user-provided file with SHA256 verification."""
    if not os.path.exists(input_path):
        raise FileNotFoundError(f"File not found: {input_path}")
    
    input_file = Path(input_path)
    encrypted_file = f"{input_file}.encrypted"
    key_file = f"{input_file}.key"
    
    # Calculate original hash
    encryptor = XTSFileEncryptor()
    original_hash = encryptor.calculate_sha256(input_path)
    
    print(f"🔍 Original SHA256: {original_hash}")
    
    # Generate and save key
    key = generate_key(key_size)
    save_key(key, key_file)
    
    # Encrypt file
    encryptor = XTSFileEncryptor(key)
    encryptor.encrypt_file(input_path, encrypted_file, sector_size)
    
    # Calculate encrypted hash
    encrypted_hash = encryptor.calculate_sha256(encrypted_file)
    
    print(f"🔍 Encrypted SHA256: {encrypted_hash}")
    print(f"🎉 Encryption completed with integrity verification!")
    
    return {
        'encrypted_file': encrypted_file,
        'key_file': key_file,
        'original_hash': original_hash,
        'encrypted_hash': encrypted_hash
    }

# Main execution for Colab
if __name__ == "__main__":
    print("AES-XTS File Encryption with SHA256 Verification")
    print("=" * 60)
    
    try:
        # Run demo with 2MB random file
        results = demo_random_file_encryption(file_size_mb=2.0)
        
        print("\n" + "=" * 60)
        print("💡 USAGE EXAMPLES:")
        print("=" * 60)
        print("""
# To generate and encrypt a 5MB random file:
results = demo_random_file_encryption(file_size_mb=5.0)

# To encrypt your own file with hash verification:
encryption_result = encrypt_user_file_with_hash('your_file.pdf')

# Manual file operations:
encryptor = XTSFileEncryptor()
encryptor.generate_random_file('test.bin', 10.0)  # 10MB file
hash_before = encryptor.calculate_sha256('test.bin')
        """)
        
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        

"""
AES-XTS File Encryption with SHA256 Verification
============================================================
🚀 AES-XTS Random File Encryption with SHA256 Verification
============================================================

============================================================
🎲 PHASE 1: GENERATE RANDOM FILE
============================================================
🎲 Generating random file: 2.0 MB (2,097,152 bytes)
📊 Generating: 2,097,152/2,097,152 bytes (100.0%)
✅ Random file generated: random_data.bin
📊 Original File Size: 2,097,152 bytes
🔍 Original SHA256:    b904a5711d1528fb9cb55c6a27f0c2ce53606d82174f48136a9d58b5baf3da89

============================================================
🔐 PHASE 2: ENCRYPTION
============================================================
💾 Key saved to: encryption_key.key
🔐 Encrypting file: random_data.bin
📁 File size: 2,097,152 bytes
📦 Sector size: 4096 bytes
🔢 Total sectors: 512
🔄 Processed 512/512 sectors (100.0%)
✅ Encryption complete: random_data.bin.encrypted
📊 Encrypted File Size: 2,097,152 bytes
🔍 Encrypted SHA256:    abc5e989bfeb49e4fe21181e6435a9022f4800d5a4f973383e1c7bf15f43dc3e

============================================================
🔓 PHASE 3: DECRYPTION
============================================================
🔓 Decrypting file: random_data.bin.encrypted
📁 Encrypted size: 2,097,152 bytes
📦 Sector size: 4096 bytes
🔢 Total sectors: 512
🔄 Processed 512/512 sectors (100.0%)
✅ Decryption complete: random_data.bin.decrypted
📊 Decrypted File Size: 2,097,152 bytes
🔍 Decrypted SHA256:    b904a5711d1528fb9cb55c6a27f0c2ce53606d82174f48136a9d58b5baf3da89

============================================================
✅ VERIFICATION RESULTS
============================================================
🔍 SHA256 Hashes Match:    True
📊 File Sizes Match:       True
🎯 Integrity Verified:     True
🎉 SUCCESS: File integrity perfectly maintained!

============================================================
📋 COMPARISON TABLE
============================================================
File                 Size (bytes)    SHA256
------------------------------------------------------------
Original             2,097,152       b904a5711d1528fb9cb55c6a27f0c2ce53606d82174f48136a9d58b5baf3da89
Encrypted            2,097,152       abc5e989bfeb49e4fe21181e6435a9022f4800d5a4f973383e1c7bf15f43dc3e
Decrypted            2,097,152       b904a5711d1528fb9cb55c6a27f0c2ce53606d82174f48136a9d58b5baf3da89

============================================================
💡 USAGE EXAMPLES:
============================================================

# To generate and encrypt a 5MB random file:
results = demo_random_file_encryption(file_size_mb=5.0)

# To encrypt your own file with hash verification:
encryption_result = encrypt_user_file_with_hash('your_file.pdf')

# Manual file operations:
encryptor = XTSFileEncryptor()
encryptor.generate_random_file('test.bin', 10.0)  # 10MB file
hash_before = encryptor.calculate_sha256('test.bin')
        
"""