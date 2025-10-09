"""
Versioning: Every stored record now contains "format_version" and "cipher_version". Current default values:

    - format_version: 1 — record-format metadata (how fields are arranged).
    - cipher_version: "xts:1" — the crypto scheme and version.
    - The migration script writes format_version: 1 and cipher_version: "xts:1".

AE-like HMAC: HMAC covers canonical_json || ciphertext.

No truncation / no collisions: Tweak allocation is global & atomic via DB (SQLite by default) or Postgres when configured.

Fernet migration caveat: To re-encrypt Fernet ciphertexts you must provide the original Fernet keys (per domain) used to encrypt them. If those keys aren't available, decryption is impossible. The migration script accepts:
    - an old_keys.json mapping domain -> base64_fernet_key, or
    - a file containing the original script that contains both ciphertext and KMS keys that you ran earlier (less common).

Dependencies: cryptography and psycopg2-binary (only if using Postgres allocator)
"""

# contextual_non_fpe.py
"""
AES-XTS + HMAC contextual encryption with persistent tweak allocator.
Supports:
 - SQLite allocator (default, file-based)
 - Postgres allocator (optional, via env/config)
Records are versioned:
 - format_version (int)
 - cipher_version (string), e.g. "xts:1"
Record fields: ciphertext, tweak, mac, json (canonical), format_version, cipher_version
"""

import os
import json
import hmac
import hashlib
import sqlite3
from typing import Dict, Any, Optional

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# Optional: Postgres support (only if you want to use Postgres allocator)
try:
    import psycopg2
except Exception:
    psycopg2 = None

# ----------------------------
# Config
# ----------------------------
DB_FILE = os.getenv("TWEAK_SQLITE_DB", "tweak_allocator.db")
USE_POSTGRES = os.getenv("TWEAK_USE_POSTGRES", "0") == "1"
POSTGRES_DSN = os.getenv("TWEAK_POSTGRES_DSN", "")  # e.g. "dbname=foo user=bar password=xyz host=pg.example.com"

# ----------------------------
# Mock KMS (replace with real KMS)
# ----------------------------
class KMS:
    """
    Mock KMS: per-domain xts_key (64 bytes) and mac_key (32 bytes).
    Replace with real KMS integration in prod.
    """
    store: Dict[str, Dict[str, bytes]] = {}

    @staticmethod
    def get_keys(domain: str) -> Dict[str, bytes]:
        if domain not in KMS.store:
            KMS.store[domain] = {
                "xts_key": os.urandom(64),  # AES-XTS 512-bit key
                "mac_key": os.urandom(32),  # HMAC-SHA256 key
            }
        return KMS.store[domain]

# ----------------------------
# Canonicalization & hashing helpers
# ----------------------------
def _canonical_json(obj: Dict[str, Any]) -> str:
    return json.dumps(obj, sort_keys=True, separators=(',', ':'))

def _hash_json(obj: Dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(obj).encode()).hexdigest()

# ----------------------------
# SQLite allocator (default)
# ----------------------------
def _init_sqlite(db_file: str = DB_FILE):
    conn = sqlite3.connect(db_file)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS tweaks (
            domain TEXT NOT NULL,
            hash TEXT NOT NULL,
            tweak BYTEA NOT NULL,
            UNIQUE(domain, hash)
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS counters (
            domain TEXT PRIMARY KEY,
            counter INTEGER NOT NULL
        )
    """)
    conn.commit()
    conn.close()

def _sqlite_conn(db_file: str = DB_FILE):
    # EXCLUSIVE mode ensures atomic counter allocation while connection open
    return sqlite3.connect(db_file, isolation_level="EXCLUSIVE")

# ----------------------------
# Postgres allocator (optional)
# ----------------------------
def _init_postgres(dsn: str):
    if psycopg2 is None:
        raise RuntimeError("psycopg2 not available; install psycopg2-binary to use Postgres allocator.")
    with psycopg2.connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS tweaks (
                    domain TEXT NOT NULL,
                    hash TEXT NOT NULL,
                    tweak BYTEA NOT NULL,
                    UNIQUE(domain, hash)
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS counters (
                    domain TEXT PRIMARY KEY,
                    counter BIGINT NOT NULL
                )
            """)
        conn.commit()

def _postgres_conn(dsn: str):
    if psycopg2 is None:
        raise RuntimeError("psycopg2 not available; install psycopg2-binary.")
    return psycopg2.connect(dsn)

# ----------------------------
# Unified allocator interface (SQLite or Postgres)
# ----------------------------
def init_allocator():
    if USE_POSTGRES:
        if not POSTGRES_DSN:
            raise RuntimeError("TWEAK_USE_POSTGRES=1 but TWEAK_POSTGRES_DSN not set")
        _init_postgres(POSTGRES_DSN)
    else:
        _init_sqlite(DB_FILE)

def allocate_or_get_tweak(json_obj: Dict[str, Any], domain: str) -> bytes:
    """
    Returns a unique 16-byte tweak for canonical json_obj within domain.
    If the canonical JSON already exists in the mapping, returns the existing tweak.
    Otherwise allocates a fresh counter and returns its 16-byte little-endian representation.
    """
    h = _hash_json(json_obj)
    if USE_POSTGRES:
        # Postgres transaction
        conn = _postgres_conn(POSTGRES_DSN)
        try:
            cur = conn.cursor()
            conn.autocommit = False
            # Try to select
            cur.execute("SELECT tweak FROM tweaks WHERE domain=%s AND hash=%s FOR SHARE", (domain, h))
            row = cur.fetchone()
            if row:
                return row[0]
            # get or init counter row FOR UPDATE
            cur.execute("SELECT counter FROM counters WHERE domain=%s FOR UPDATE", (domain,))
            r = cur.fetchone()
            if r:
                counter = r[0]
                cur.execute("UPDATE counters SET counter=%s WHERE domain=%s", (counter + 1, domain))
            else:
                counter = 0
                cur.execute("INSERT INTO counters(domain,counter) VALUES(%s,%s)", (domain, 1))
            tweak = int(counter).to_bytes(16, "little")
            cur.execute("INSERT INTO tweaks(domain, hash, tweak) VALUES(%s,%s,%s)", (domain, h, tweak))
            conn.commit()
            return tweak
        finally:
            conn.close()
    else:
        conn = _sqlite_conn(DB_FILE)
        try:
            cur = conn.cursor()
            cur.execute("BEGIN EXCLUSIVE")
            cur.execute("SELECT tweak FROM tweaks WHERE domain=? AND hash=?", (domain, h))
            row = cur.fetchone()
            if row:
                return row[0]
            cur.execute("SELECT counter FROM counters WHERE domain=?", (domain,))
            r = cur.fetchone()
            counter = r[0] if r else 0
            tweak = int(counter).to_bytes(16, "little")
            if r:
                cur.execute("UPDATE counters SET counter=? WHERE domain=?", (counter + 1, domain))
            else:
                cur.execute("INSERT INTO counters(domain,counter) VALUES(?,?)", (domain, counter + 1))
            cur.execute("INSERT INTO tweaks(domain, hash, tweak) VALUES(?,?,?)", (domain, h, tweak))
            conn.commit()
            return tweak
        finally:
            conn.close()

# ----------------------------
# Crypto primitives
# ----------------------------
def _xts_cipher(xts_key: bytes, tweak16: bytes):
    if len(xts_key) != 64:
        raise ValueError("XTS key must be 64 bytes (512-bit).")
    if len(tweak16) != 16:
        raise ValueError("tweak must be 16 bytes.")
    return Cipher(algorithms.AES(xts_key), modes.XTS(tweak16), backend=default_backend())

def encrypt_with_tweak(plaintext: bytes, domain: str, tweak16: bytes) -> bytes:
    keys = KMS.get_keys(domain)
    cipher = _xts_cipher(keys["xts_key"], tweak16)
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    return encryptor.update(padded) + encryptor.finalize()

def decrypt_with_tweak(ciphertext: bytes, domain: str, tweak16: bytes) -> bytes:
    keys = KMS.get_keys(domain)
    cipher = _xts_cipher(keys["xts_key"], tweak16)
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()

def compute_hmac_over_json_and_ciphertext(json_obj: Dict[str, Any], ciphertext: bytes, domain: str) -> bytes:
    keys = KMS.get_keys(domain)
    mac_key = keys["mac_key"]
    canonical = _canonical_json(json_obj).encode()
    return hmac.new(mac_key, canonical + ciphertext, hashlib.sha256).digest()

# ----------------------------
# Record format (versioned)
# ----------------------------
FORMAT_VERSION = 1
CIPHER_VERSION = "xts:1"

# In-memory store (replace with DB if you want)
STORAGE: Dict[str, list] = {}

def encrypt_ssn(ssn: str, domain: str, json_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    if json_context is None:
        json_context = {"context": domain, "data": ssn}

    canonical = _canonical_json(json_context)
    tweak = allocate_or_get_tweak(json_context, domain)
    ciphertext = encrypt_with_tweak(ssn.encode(), domain, tweak)
    mac = compute_hmac_over_json_and_ciphertext(json_context, ciphertext, domain)

    record = {
        "format_version": FORMAT_VERSION,
        "cipher_version": CIPHER_VERSION,
        "ciphertext": ciphertext.hex(),
        "tweak": tweak.hex(),
        "mac": mac.hex(),
        "json": canonical,
    }
    STORAGE.setdefault(domain, []).append(record)
    return record

def decrypt_ssn(record: Dict[str, Any], domain: str) -> str:
    if record.get("format_version") != FORMAT_VERSION:
        raise ValueError("Unsupported record format version: {}".format(record.get("format_version")))

    json_obj = json.loads(record["json"])
    ciphertext = bytes.fromhex(record["ciphertext"])
    expected_mac = bytes.fromhex(record["mac"])
    computed_mac = compute_hmac_over_json_and_ciphertext(json_obj, ciphertext, domain)
    if not hmac.compare_digest(expected_mac, computed_mac):
        raise ValueError("HMAC mismatch — integrity check failed or wrong domain/key.")

    tweak = bytes.fromhex(record["tweak"])
    pt = decrypt_with_tweak(ciphertext, domain, tweak)
    return pt.decode()

def verify_ssn_across_domains(domain_storage: Dict[str, list], ssn_plaintext: str, authorized_domains: list):
    matches = []
    for domain in authorized_domains:
        for rec in domain_storage.get(domain, []):
            try:
                if decrypt_ssn(rec, domain) == ssn_plaintext:
                    matches.append(domain)
                    break
            except Exception:
                pass
    return matches

# ----------------------------
# Init allocator on import or run
# ----------------------------
init_allocator()

# ----------------------------
# Example (if run directly)
# ----------------------------
if __name__ == "__main__":
    # quick demo
    print("Initializing allocator and running demo...")
    rec = encrypt_ssn("123-45-6789", "finance", {"context":"finance","data":"123-45-6789"})
    print(json.dumps(rec, indent=2))
    print("Decrypted:", decrypt_ssn(rec, "finance"))

"""
Initializing allocator and running demo...
{
  "format_version": 1,
  "cipher_version": "xts:1",
  "ciphertext": "6306b1071aa3aa11e4674670c53d1519",
  "tweak": "00000000000000000000000000000000",
  "mac": "e13513b16e21dcf457380ee0d2827fc13bfa563bacfe33ec82d2baf78ba49f0d",
  "json": "{\"context\":\"finance\",\"data\":\"123-45-6789\"}"
}
Decrypted: 123-45-6789
"""

#!/usr/bin/env python3
"""
Migration helper: decrypt existing Fernet ciphertexts and re-encrypt into the new AES-XTS + HMAC scheme.

Looks for:
  - old_storage.json  : Fernet-encrypted records (domain → list of tokens or objects)
  - old_keys.json     : domain → base64url Fernet key
Writes:
  - new_records.json  : AES-XTS + HMAC versioned records compatible with contextual_non_fpe.py
  - migration_report.json : Detailed migration statistics and errors

Features:
  - Automatic backup of existing new_records.json
  - Comprehensive error tracking and reporting
  - Migration statistics (success/failure counts per domain)
  - Preserves original metadata when available

Usage:
    python migrate_fernet_to_xts.py
    
    Or in notebook:
    %run migrate_fernet_to_xts.py
"""

import json
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Tuple
from cryptography.fernet import Fernet
#from contextual_non_fpe import encrypt_ssn


# Default file paths
OLD_STORAGE_FILE = Path("old_storage.json")
OLD_KEYS_FILE = Path("old_keys.json")
OUT_FILE = Path("new_records.json")
REPORT_FILE = Path("migration_report.json")
BACKUP_SUFFIX = ".backup"


class MigrationStats:
    """Track migration statistics per domain."""
    
    def __init__(self):
        self.stats: Dict[str, Dict[str, Any]] = {}
        self.global_errors: List[str] = []
        self.start_time = datetime.now()
    
    def init_domain(self, domain: str, total_records: int):
        """Initialize stats for a domain."""
        self.stats[domain] = {
            "total_records": total_records,
            "successful": 0,
            "failed": 0,
            "decrypt_errors": [],
            "encrypt_errors": []
        }
    
    def record_success(self, domain: str):
        """Record successful migration."""
        self.stats[domain]["successful"] += 1
    
    def record_decrypt_error(self, domain: str, error: str, index: int):
        """Record decryption failure."""
        self.stats[domain]["failed"] += 1
        self.stats[domain]["decrypt_errors"].append({
            "index": index,
            "error": str(error)
        })
    
    def record_encrypt_error(self, domain: str, error: str, index: int):
        """Record re-encryption failure."""
        self.stats[domain]["failed"] += 1
        self.stats[domain]["encrypt_errors"].append({
            "index": index,
            "error": str(error)
        })
    
    def add_global_error(self, error: str):
        """Record global migration error."""
        self.global_errors.append(error)
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive migration report."""
        end_time = datetime.now()
        duration = (end_time - self.start_time).total_seconds()
        
        total_records = sum(s["total_records"] for s in self.stats.values())
        total_successful = sum(s["successful"] for s in self.stats.values())
        total_failed = sum(s["failed"] for s in self.stats.values())
        
        return {
            "migration_timestamp": self.start_time.isoformat(),
            "duration_seconds": duration,
            "summary": {
                "total_records": total_records,
                "successful": total_successful,
                "failed": total_failed,
                "success_rate": f"{(total_successful/total_records*100):.2f}%" if total_records > 0 else "N/A"
            },
            "domains": self.stats,
            "global_errors": self.global_errors
        }


def backup_existing_output(output_path: Path) -> bool:
    """Create backup of existing output file if it exists."""
    if output_path.exists():
        backup_path = output_path.with_suffix(output_path.suffix + BACKUP_SUFFIX)
        try:
            output_path.rename(backup_path)
            print(f"[INFO] Backed up existing {output_path.name} → {backup_path.name}")
            return True
        except Exception as e:
            print(f"[ERROR] Failed to backup {output_path.name}: {e}")
            return False
    return True


def extract_metadata(entry: Any) -> Tuple[str, Dict[str, Any]]:
    """Extract Fernet token and any metadata from entry."""
    if isinstance(entry, dict):
        # Entry has metadata
        token = entry.get("ciphertext", entry.get("token", ""))
        metadata = {k: v for k, v in entry.items() if k not in ("ciphertext", "token")}
        return token, metadata
    else:
        # Entry is raw token string
        return str(entry), {}


def build_context(domain: str, plaintext: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
    """Build context object for re-encryption, preserving metadata."""
    context = {
        "context": domain,
        "data": plaintext
    }
    # Preserve original metadata if available
    if metadata:
        context["original_metadata"] = metadata
    return context


def migrate_domain(
    domain: str,
    items: List[Any],
    fernet_key: str,
    stats: MigrationStats
) -> List[Dict[str, Any]]:
    """Migrate all records for a single domain."""
    
    try:
        fernet = Fernet(fernet_key.encode() if isinstance(fernet_key, str) else fernet_key)
    except Exception as e:
        stats.add_global_error(f"Invalid Fernet key for domain '{domain}': {e}")
        return []
    
    stats.init_domain(domain, len(items))
    new_records = []
    
    for idx, entry in enumerate(items):
        try:
            # Extract token and metadata
            token, metadata = extract_metadata(entry)
            
            if not token:
                stats.record_decrypt_error(domain, "Empty or missing token", idx)
                continue
            
            # Decrypt old format
            try:
                plaintext = fernet.decrypt(token.encode())
                plaintext_str = plaintext.decode()
            except Exception as e:
                stats.record_decrypt_error(domain, f"Decryption failed: {e}", idx)
                continue
            
            # Re-encrypt in new scheme
            try:
                context = build_context(domain, plaintext_str, metadata)
                new_record = encrypt_ssn(plaintext_str, domain, context)
                new_records.append(new_record)
                stats.record_success(domain)
            except Exception as e:
                stats.record_encrypt_error(domain, f"Re-encryption failed: {e}", idx)
        
        except Exception as e:
            stats.record_decrypt_error(domain, f"Unexpected error: {e}", idx)
    
    return new_records


def migrate_now():
    """Execute migration with comprehensive error handling and reporting."""
    
    print(f"{'='*60}")
    print(f"Fernet → AES-XTS+HMAC Migration")
    print(f"{'='*60}\n")
    
    stats = MigrationStats()
    
    # --- Validation phase ---
    print("[1/5] Validating input files...")
    
    if not OLD_STORAGE_FILE.exists():
        print(f"[ERROR] Missing {OLD_STORAGE_FILE.name}")
        print(f"\n💡 Demo mode: Creating sample files...")
        create_demo_files()
        return
    
    if not OLD_KEYS_FILE.exists():
        print(f"[ERROR] Missing {OLD_KEYS_FILE.name}")
        print(f"\n💡 Demo mode: Creating sample files...")
        create_demo_files()
        return
    
    print(f"  ✓ Found {OLD_STORAGE_FILE.name}")
    print(f"  ✓ Found {OLD_KEYS_FILE.name}")
    
    # --- Backup phase ---
    print(f"\n[2/5] Creating backups...")
    if not backup_existing_output(OUT_FILE):
        print("[WARN] Proceeding without backup...")
    
    # --- Load phase ---
    print(f"\n[3/5] Loading input data...")
    
    try:
        with OLD_STORAGE_FILE.open("r") as f:
            old_storage = json.load(f)
        print(f"  ✓ Loaded {len(old_storage)} domains from storage")
    except Exception as e:
        print(f"[ERROR] Failed to load {OLD_STORAGE_FILE.name}: {e}")
        return
    
    try:
        with OLD_KEYS_FILE.open("r") as f:
            old_keys = json.load(f)
        print(f"  ✓ Loaded {len(old_keys)} domain keys")
    except Exception as e:
        print(f"[ERROR] Failed to load {OLD_KEYS_FILE.name}: {e}")
        return
    
    # --- Migration phase ---
    print(f"\n[4/5] Migrating records...")
    
    new_records = {}
    
    for domain, items in old_storage.items():
        key_b64 = old_keys.get(domain)
        
        if not key_b64:
            msg = f"No Fernet key for domain '{domain}' — skipping {len(items)} records"
            print(f"  [WARN] {msg}")
            stats.add_global_error(msg)
            continue
        
        print(f"  → Processing domain '{domain}' ({len(items)} records)...")
        
        migrated = migrate_domain(domain, items, key_b64, stats)
        
        if migrated:
            new_records[domain] = migrated
        
        domain_stats = stats.stats[domain]
        print(f"    ✓ Success: {domain_stats['successful']}, Failed: {domain_stats['failed']}")
    
    # --- Output phase ---
    print(f"\n[5/5] Writing output...")
    
    if new_records:
        try:
            with OUT_FILE.open("w") as f:
                json.dump(new_records, f, indent=2)
            print(f"  ✓ Wrote {OUT_FILE.name}")
        except Exception as e:
            print(f"[ERROR] Failed to write {OUT_FILE.name}: {e}")
            stats.add_global_error(f"Output write failed: {e}")
    else:
        print(f"  [WARN] No records to write — {OUT_FILE.name} not created")
    
    # --- Report phase ---
    report = stats.generate_report()
    
    try:
        with REPORT_FILE.open("w") as f:
            json.dump(report, f, indent=2)
        print(f"  ✓ Wrote {REPORT_FILE.name}")
    except Exception as e:
        print(f"[WARN] Failed to write report: {e}")
    
    # --- Summary ---
    print(f"\n{'='*60}")
    print("MIGRATION SUMMARY")
    print(f"{'='*60}")
    print(f"Total records:  {report['summary']['total_records']}")
    print(f"Successful:     {report['summary']['successful']}")
    print(f"Failed:         {report['summary']['failed']}")
    print(f"Success rate:   {report['summary']['success_rate']}")
    print(f"Duration:       {report['duration_seconds']:.2f}s")
    
    if stats.global_errors:
        print(f"\nGlobal errors: {len(stats.global_errors)}")
        for err in stats.global_errors[:5]:
            print(f"  • {err}")
        if len(stats.global_errors) > 5:
            print(f"  ... and {len(stats.global_errors) - 5} more (see {REPORT_FILE.name})")
    
    print(f"\nDetailed report: {REPORT_FILE.name}")
    print(f"{'='*60}\n")


def create_demo_files():
    """Create demo input files for testing."""
    print("Creating demo Fernet-encrypted files...\n")
    
    # Generate demo keys and encrypted data
    domains = ["finance", "healthcare", "hr"]
    demo_keys = {}
    demo_storage = {}
    
    for domain in domains:
        key = Fernet.generate_key()
        demo_keys[domain] = key.decode()
        fernet = Fernet(key)
        
        # Create some demo encrypted SSNs
        ssns = [f"{i:03d}-{j:02d}-{k:04d}" for i, j, k in [(123, 45, 6789), (987, 65, 4321), (555, 12, 3456)]]
        demo_storage[domain] = [fernet.encrypt(ssn.encode()).decode() for ssn in ssns]
    
    # Write files
    with OLD_KEYS_FILE.open("w") as f:
        json.dump(demo_keys, f, indent=2)
    print(f"✓ Created {OLD_KEYS_FILE.name}")
    
    with OLD_STORAGE_FILE.open("w") as f:
        json.dump(demo_storage, f, indent=2)
    print(f"✓ Created {OLD_STORAGE_FILE.name}")
    
    print(f"\nDemo files created! Run the script again to migrate:\n")
    print(f"  python migrate_fernet_to_xts.py")
    print(f"  or: %run migrate_fernet_to_xts.py\n")


if __name__ == "__main__":
    migrate_now()

"""
============================================================
Fernet → AES-XTS+HMAC Migration
============================================================

[1/5] Validating input files...
[ERROR] Missing old_storage.json

💡 Demo mode: Creating sample files...
Creating demo Fernet-encrypted files...

✓ Created old_keys.json
✓ Created old_storage.json

Demo files created! Run the script again to migrate:

  python migrate_fernet_to_xts.py
  or: %run migrate_fernet_to_xts.py

"""
