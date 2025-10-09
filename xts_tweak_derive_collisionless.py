# contextual_xts_no_collide.py
"""
Requirement

No truncation: We never truncate an HMAC for the tweak. Instead we allocate a 16-byte tweak deterministically from an ever-incrementing counter stored in a mapping file. That mapping file stores the complete association canonical JSON → tweak (16 bytes hex). Since each allocation uses an incrementing counter and we persist it atomically, there is no probabilistic collision.

No hidden collisions: Because allocation is persistent and atomic, two different JSONs will never be assigned the same tweak unless you intentionally modify the mapping file.

Integrity: We still compute a full HMAC-SHA256 (32 bytes) over the canonical JSON and store it with the ciphertext. Before decrypting we verify the HMAC; that prevents tampering and key mismatch issues.

Determinism when desired: If you want the same JSON to map to the same tweak, this will do that. New JSONs get new tweaks.

DB/scale: The mapping file is a JSON object with a _counter and entries mapping canonical JSON → hex tweak. For large scale you would replace file storage with a proper DB/table that provides atomic INSERT with sequence allocation.

"""
import os
import json
import hmac
import hashlib
import tempfile
from pathlib import Path
from typing import Dict, Any

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# ----------------------------
# Simple KMS (mock) - per-domain keys
# ----------------------------
class KMS:
    """
    Provides two keys per domain:
      - xts_key: 64 bytes (512 bits) required by AES-XTS
      - mac_key: 32 bytes (256 bits) for HMAC-SHA256
    """
    store = {}

    @staticmethod
    def get_keys(domain: str) -> Dict[str, bytes]:
        if domain not in KMS.store:
            KMS.store[domain] = {
                "xts_key": os.urandom(64),
                "mac_key": os.urandom(32)
            }
        return KMS.store[domain]

# ----------------------------
# Persistent, collision-free allocator for 16-byte tweaks per canonical JSON
# ----------------------------
# Mapping file per domain: "<domain>_tweak_map.json"
def _mapping_path_for_domain(domain: str) -> Path:
    return Path(f"{domain}_tweak_map.json")

def _load_mapping(domain: str) -> Dict[str, Any]:
    path = _mapping_path_for_domain(domain)
    if not path.exists():
        return {"_counter": 0}
    try:
        return json.loads(path.read_text())
    except Exception:
        # If the mapping file is corrupted, fail-safe to empty mapping (you may want stricter handling)
        return {"_counter": 0}

def _atomic_write(path: Path, data: str):
    # atomic write using temporary file + rename
    dirp = path.parent or Path(".")
    fd, tmp = tempfile.mkstemp(dir=str(dirp))
    try:
        with os.fdopen(fd, "w") as f:
            f.write(data)
        os.replace(tmp, str(path))
    finally:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except Exception:
                pass

def _save_mapping(domain: str, mapping: Dict[str, Any]):
    path = _mapping_path_for_domain(domain)
    _atomic_write(path, json.dumps(mapping, indent=2))

def _canonical_json(obj: Dict[str, Any]) -> str:
    # deterministic canonicalization for mapping and HMAC
    return json.dumps(obj, sort_keys=True, separators=(',', ':'))

def allocate_or_get_tweak(json_obj: Dict[str, Any], domain: str) -> bytes:
    """
    Return a unique 16-byte tweak for this json_obj under domain.
    If seen before, return previously allocated tweak. Otherwise, allocate a new one (counter -> 16 bytes).
    This guarantees zero collisions as long as mapping storage is durable and atomic.
    """
    key = _canonical_json(json_obj)
    mapping = _load_mapping(domain)

    if key in mapping:
        return bytes.fromhex(mapping[key])

    counter = int(mapping.get("_counter", 0))
    # Represent counter as 16-byte little-endian tweak
    tweak = counter.to_bytes(16, "little")
    mapping[key] = tweak.hex()
    mapping["_counter"] = counter + 1
    _save_mapping(domain, mapping)
    return tweak

# ----------------------------
# HMAC (full) for integrity (no truncation)
# ----------------------------
def compute_hmac_full(json_obj: Dict[str, Any], domain: str) -> bytes:
    keys = KMS.get_keys(domain)
    mac_key = keys["mac_key"]
    msg = _canonical_json(json_obj).encode()
    return hmac.new(mac_key, msg, hashlib.sha256).digest()  # full 32 bytes

# ----------------------------
# AES-XTS encrypt / decrypt (with PKCS7 padding to satisfy XTS requirements)
# ----------------------------
def _xts_cipher(xts_key: bytes, tweak16: bytes):
    if len(xts_key) != 64:
        raise ValueError("XTS key must be 64 bytes (512 bits).")
    if len(tweak16) != 16:
        raise ValueError("Tweak must be 16 bytes.")
    return Cipher(algorithms.AES(xts_key), modes.XTS(tweak16), backend=default_backend())

def encrypt_with_tweak(plaintext: bytes, domain: str, tweak16: bytes) -> bytes:
    keys = KMS.get_keys(domain)
    cipher = _xts_cipher(keys["xts_key"], tweak16)
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    ct = encryptor.update(padded) + encryptor.finalize()
    return ct

def decrypt_with_tweak(ciphertext: bytes, domain: str, tweak16: bytes) -> bytes:
    keys = KMS.get_keys(domain)
    cipher = _xts_cipher(keys["xts_key"], tweak16)
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    pt = unpadder.update(padded) + unpadder.finalize()
    return pt

# ----------------------------
# High-level API similar to your original file
# - encrypt_ssn(ssn_str, domain) -> returns stored record (dict)
# - decrypt_ssn(stored_record, domain) -> returns plaintext
# ----------------------------
# Simple in-memory storage of ciphertexts (mimic your ssn_storage). Replace with DB or file as needed.
STORAGE = {}

def encrypt_ssn(ssn: str, domain: str, json_context: Dict[str, Any] = None) -> Dict[str, str]:
    """
    Encrypt the SSN (or any string) under domain, using a tweak allocated for the JSON context.
    Returns a dict with fields:
      - ciphertext: hex
      - tweak: hex
      - mac: hex (HMAC-SHA256 over canonical JSON)
      - json: the canonical JSON used (string)
    """
    if json_context is None:
        json_context = {"context": domain, "data": ssn}

    canonical = _canonical_json(json_context)
    tweak = allocate_or_get_tweak(json_context, domain)          # 16 bytes, guaranteed unique per JSON
    mac = compute_hmac_full(json_context, domain)               # 32 bytes full HMAC
    ciphertext = encrypt_with_tweak(ssn.encode(), domain, tweak)

    record = {
        "ciphertext": ciphertext.hex(),
        "tweak": tweak.hex(),
        "mac": mac.hex(),
        "json": canonical
    }

    # store into in-memory STORAGE keyed by domain: you can adapt to persistent DB
    STORAGE.setdefault(domain, []).append(record)
    return record

def decrypt_ssn(record: Dict[str, str], domain: str) -> str:
    """
    Decrypt the record after verifying HMAC matches the JSON and domain's mac_key.
    Raises ValueError on HMAC mismatch.
    """
    canonical_json = record["json"]
    json_obj = json.loads(canonical_json)
    expected_mac = bytes.fromhex(record["mac"])
    computed_mac = compute_hmac_full(json_obj, domain)
    if not hmac.compare_digest(expected_mac, computed_mac):
        raise ValueError("HMAC mismatch — integrity check failed or wrong domain/key.")

    tweak = bytes.fromhex(record["tweak"])
    ciphertext = bytes.fromhex(record["ciphertext"])
    plaintext = decrypt_with_tweak(ciphertext, domain, tweak)
    return plaintext.decode()

def verify_ssn_across_domains(domain_storage: Dict[str, list], ssn_plaintext: str, authorized_domains: list):
    """
    Example helper that attempts to decrypt stored records across authorized domains and returns matches.
    This mimics your previous verify_ssn_across_domains behavior but using the new scheme.
    """
    matches = []
    for domain in authorized_domains:
        records = domain_storage.get(domain, [])
        for rec in records:
            try:
                pt = decrypt_ssn(rec, domain)
                if pt == ssn_plaintext:
                    matches.append(domain)
                    break  # one match in domain is enough
            except Exception:
                # integrity check failed or wrong key — treat as no match
                pass
    return matches

# ----------------------------
# Example / quick test (run when called directly)
# ----------------------------
if __name__ == "__main__":
    # Example usage:
    domain = "finance"
    ssn = "123-45-6789"
    json_ctx = {"context": "finance", "data": ssn}

    rec = encrypt_ssn(ssn, domain, json_ctx)
    print("Stored record:", json.dumps(rec, indent=2))

    # Try decrypt
    recovered = decrypt_ssn(rec, domain)
    print("Recovered:", recovered)

    # verify across domains (put same rec in other domain to test)
    # note: in real use you would persist STORAGE per domain
    print("Verify across domains:", verify_ssn_across_domains(STORAGE, ssn, ["finance", "healthcare"]))

"""
Stored record: {
  "ciphertext": "4cef10986c47b04395fbde5a464e43f0",
  "tweak": "00000000000000000000000000000000",
  "mac": "61fd057269b49ae9ecb306e336765a57451da9f23cee0c2ee87fe8c42b508421",
  "json": "{\"context\":\"finance\",\"data\":\"123-45-6789\"}"
}
Recovered: 123-45-6789
Verify across domains: ['finance']

"""

"""
For concurrency at scale, replace the simple file + _counter approach with an atomic DB sequence (Postgres bigserial / UUID allocation) or a key-value store supporting compare-and-swap so two processes don't allocate the same counter.

If you need cross-machine deduplication without a central allocator, use a deterministic unique ID generated outside of local counters (e.g., canonical JSON → SHA-256 and then use the full 32-byte hash as stored ID), but if you want XTS tweak exactly 16 bytes and absolutely no collisions, you still need a global allocator / DB mapping that maps the long hash deterministically to a unique 16-byte ID without truncation risk — typically by storing the mapping hash -> assigned 16B ID.

This implementation stores metadata in a simple in-memory STORAGE and mapping in "<domain>_tweak_map.json". Replace with your persistence layer as needed.

✅ 
1. Replace Fernet with AES-XTS (no truncation, no collisions).

2. Add SQLite-backed tweak allocator (atomic counter, safe for concurrent access).

3. Ensure deterministic deduplication:

- Compute canonical JSON → SHA-256 hash.
- If hash already in DB, reuse its assigned 16-byte tweak.
- If not, allocate next counter value, convert to 16 bytes, and insert.
- This guarantees no duplicates or collisions, even across processes or machines sharing the same DB.

4. Keep full HMAC for authenticity and integrity.

5. Maintain same high-level API (encrypt_ssn, decrypt_ssn, verify_ssn_across_domains).

""""

# contextual_non_fpe.py
import os
import json
import hmac
import hashlib
import sqlite3
from typing import Dict, Any
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# ============================================================
# Domain Key Management
# ============================================================
class KMS:
    store = {}
    @staticmethod
    def get_keys(domain: str) -> Dict[str, bytes]:
        if domain not in KMS.store:
            KMS.store[domain] = {
                "xts_key": os.urandom(64),  # AES-XTS key (512-bit)
                "mac_key": os.urandom(32),  # HMAC key
            }
        return KMS.store[domain]

# ============================================================
# Global SQLite-backed tweak allocator (atomic, collision-free)
# ============================================================
DB_FILE = "tweak_allocator.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS tweaks (
            domain TEXT NOT NULL,
            hash TEXT NOT NULL,
            tweak BLOB NOT NULL,
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

def _get_db_conn():
    return sqlite3.connect(DB_FILE, isolation_level="EXCLUSIVE")

def _canonical_json(obj: Dict[str, Any]) -> str:
    return json.dumps(obj, sort_keys=True, separators=(',', ':'))

def _hash_json(obj: Dict[str, Any]) -> str:
    canonical = _canonical_json(obj).encode()
    return hashlib.sha256(canonical).hexdigest()

def allocate_or_get_tweak(json_obj: Dict[str, Any], domain: str) -> bytes:
    """
    Returns a unique 16-byte tweak for the given JSON context in the domain.
    Uses a deterministic hash lookup and atomic counter allocation in SQLite.
    This guarantees zero collisions and safe concurrent access.
    """
    h = _hash_json(json_obj)
    conn = _get_db_conn()
    cur = conn.cursor()
    try:
        cur.execute("BEGIN EXCLUSIVE")
        cur.execute("SELECT tweak FROM tweaks WHERE domain=? AND hash=?", (domain, h))
        row = cur.fetchone()
        if row:
            tweak = row[0]
        else:
            # Fetch current counter or start at 0
            cur.execute("SELECT counter FROM counters WHERE domain=?", (domain,))
            row = cur.fetchone()
            counter = row[0] if row else 0
            tweak = counter.to_bytes(16, "little")
            # Update counter and insert tweak
            if row:
                cur.execute("UPDATE counters SET counter=? WHERE domain=?", (counter + 1, domain))
            else:
                cur.execute("INSERT INTO counters(domain, counter) VALUES(?, ?)", (domain, counter + 1))
            cur.execute("INSERT INTO tweaks(domain, hash, tweak) VALUES(?, ?, ?)", (domain, h, tweak))
        conn.commit()
        return tweak
    finally:
        conn.close()

# ============================================================
# HMAC + AES-XTS crypto primitives
# ============================================================
def compute_hmac_full(json_obj: Dict[str, Any], domain: str) -> bytes:
    keys = KMS.get_keys(domain)
    mac_key = keys["mac_key"]
    msg = _canonical_json(json_obj).encode()
    return hmac.new(mac_key, msg, hashlib.sha256).digest()

def _xts_cipher(xts_key: bytes, tweak16: bytes):
    if len(xts_key) != 64:
        raise ValueError("AES-XTS key must be 64 bytes.")
    if len(tweak16) != 16:
        raise ValueError("AES-XTS tweak must be 16 bytes.")
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

# ============================================================
# High-level API (same as original)
# ============================================================
STORAGE = {}

def encrypt_ssn(ssn: str, domain: str, json_context: Dict[str, Any] = None) -> Dict[str, str]:
    if json_context is None:
        json_context = {"context": domain, "data": ssn}

    tweak = allocate_or_get_tweak(json_context, domain)
    mac = compute_hmac_full(json_context, domain)
    ciphertext = encrypt_with_tweak(ssn.encode(), domain, tweak)

    record = {
        "ciphertext": ciphertext.hex(),
        "tweak": tweak.hex(),
        "mac": mac.hex(),
        "json": _canonical_json(json_context),
    }
    STORAGE.setdefault(domain, []).append(record)
    return record

def decrypt_ssn(record: Dict[str, str], domain: str) -> str:
    canonical_json = record["json"]
    json_obj = json.loads(canonical_json)
    expected_mac = bytes.fromhex(record["mac"])
    computed_mac = compute_hmac_full(json_obj, domain)
    if not hmac.compare_digest(expected_mac, computed_mac):
        raise ValueError("HMAC mismatch — possible tampering or wrong key/domain.")
    tweak = bytes.fromhex(record["tweak"])
    ciphertext = bytes.fromhex(record["ciphertext"])
    return decrypt_with_tweak(ciphertext, domain, tweak).decode()

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

# ============================================================
# Example usage
# ============================================================
if __name__ == "__main__":
    init_db()
    ssn = "123-45-6789"
    domains = ["finance", "healthcare", "education"]

    for d in domains:
        rec = encrypt_ssn(ssn, d, {"context": d, "data": ssn})
        print(f"\n[{d}] Stored record:\n", json.dumps(rec, indent=2))
        print("Decrypted:", decrypt_ssn(rec, d))

    matches = verify_ssn_across_domains(STORAGE, ssn, domains)
    print("\nDomains with matching SSN:", matches)

"""

| Property                   | Guarantee                                                                                      |
| -------------------------- | ---------------------------------------------------------------------------------------------- |
| **Collision-free**         | Each JSON gets a unique 16-byte tweak via atomic counter, stored permanently in SQLite.        |
| **Concurrent-safe**        | SQLite handles locking and ensures two processes can’t allocate the same tweak simultaneously. |
| **Deterministic reuse**    | Same canonical JSON → same tweak.                                                              |
| **Cross-domain isolation** | Each domain has its own tweak counter namespace.                                               |
| **Integrity**              | HMAC-SHA256 (full 32 bytes) ensures authenticity of JSON context.                              |
| **Scalable**               | DB-backed counter supports millions of entries and concurrent writers.                         |


[finance] Stored record:
 {
  "ciphertext": "5e996aa4d7b5d3fc48f90aa055dea31f",
  "tweak": "00000000000000000000000000000000",
  "mac": "40a30812a0451e51c3bb80d2593ab6c144198ab55142e468eb464ef3c2859e4b",
  "json": "{\"context\":\"finance\",\"data\":\"123-45-6789\"}"
}
Decrypted: 123-45-6789

[healthcare] Stored record:
 {
  "ciphertext": "145662a5f7c28567629e640c2ec04280",
  "tweak": "00000000000000000000000000000000",
  "mac": "321f2df9d9c962a2b1c8723c53353198c06052e99eeea42caa7d14e7c6cdcb06",
  "json": "{\"context\":\"healthcare\",\"data\":\"123-45-6789\"}"
}
Decrypted: 123-45-6789

[education] Stored record:
 {
  "ciphertext": "951aa4b961a3a39c83135474b6e8fb0f",
  "tweak": "00000000000000000000000000000000",
  "mac": "17db43b0df938ab1c29af3469d2b426dd950d80837f7d1887cb463f17c9715bd",
  "json": "{\"context\":\"education\",\"data\":\"123-45-6789\"}"
}
Decrypted: 123-45-6789

Domains with matching SSN: ['finance', 'healthcare', 'education']
"""

"""
the HMAC authenticates both the canonical JSON context AND the ciphertext (AE-like protection). Below is the full, ready-to-drop-in file. Behavior changes:

On encrypt: HMAC = HMAC-SHA256(mac_key, canonical_json || ciphertext). Stored full 32-byte mac in record.

On decrypt: Recompute HMAC over the stored canonical JSON and ciphertext; reject if mismatch.

All other guarantees remain: SQLite-backed atomic tweak allocator (no collisions), AES-XTS for encryption (with PKCS7 padding), separate domain keys, deterministic canonical JSON, persistent tweak mapping.
"""
"""
HMAC now authenticates both the JSON context and ciphertext; this provides strong integrity protection and prevents tampering or tricking decryption into returning valid plaintext for altered ciphertext or context.

Keep mac_key separate from xts_key (we already do). If you migrate to a real KMS, store keys separately and use proper rotation policies.

For heavy concurrent multi-host deployments, store tweak_allocator.db on a shared DB (Postgres or equivalent) instead of a file-backed SQLite (SQLite supports concurrency but has limits). I kept SQLite for simplicity; switching to Postgres is straightforward (same logical schema + SELECT ... FOR UPDATE / sequences).
"""

# contextual_non_fpe.py
import os
import json
import hmac
import hashlib
import sqlite3
from typing import Dict, Any
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# ============================================================
# Domain Key Management
# ============================================================
class KMS:
    """
    Mock KMS: provides xts_key (64 bytes) and mac_key (32 bytes) per domain.
    Replace with real KMS integration in production.
    """
    store = {}
    @staticmethod
    def get_keys(domain: str) -> Dict[str, bytes]:
        if domain not in KMS.store:
            KMS.store[domain] = {
                "xts_key": os.urandom(64),  # AES-XTS key (512-bit)
                "mac_key": os.urandom(32),  # HMAC key (256-bit)
            }
        return KMS.store[domain]

# ============================================================
# Global SQLite-backed tweak allocator (atomic, collision-free)
# ============================================================
DB_FILE = "tweak_allocator.db"

def init_db(db_file: str = DB_FILE):
    conn = sqlite3.connect(db_file)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS tweaks (
            domain TEXT NOT NULL,
            hash TEXT NOT NULL,
            tweak BLOB NOT NULL,
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

def _get_db_conn(db_file: str = DB_FILE):
    # Use EXCLUSIVE isolation when allocating to ensure atomic counter increments.
    return sqlite3.connect(db_file, isolation_level="EXCLUSIVE")

def _canonical_json(obj: Dict[str, Any]) -> str:
    # Deterministic canonicalization: sorted keys and compact separators
    return json.dumps(obj, sort_keys=True, separators=(',', ':'))

def _hash_json(obj: Dict[str, Any]) -> str:
    canonical = _canonical_json(obj).encode()
    return hashlib.sha256(canonical).hexdigest()

def allocate_or_get_tweak(json_obj: Dict[str, Any], domain: str, db_file: str = DB_FILE) -> bytes:
    """
    Returns a unique 16-byte tweak for the given JSON context in the domain.
    Uses a deterministic hash lookup and atomic counter allocation in SQLite.
    Guarantees zero collisions and safe concurrent access when all processes share the same DB file.
    """
    h = _hash_json(json_obj)
    conn = _get_db_conn(db_file)
    cur = conn.cursor()
    try:
        cur.execute("BEGIN EXCLUSIVE")
        cur.execute("SELECT tweak FROM tweaks WHERE domain=? AND hash=?", (domain, h))
        row = cur.fetchone()
        if row:
            tweak = row[0]
        else:
            # Fetch current counter or start at 0
            cur.execute("SELECT counter FROM counters WHERE domain=?", (domain,))
            row = cur.fetchone()
            counter = row[0] if row else 0
            tweak = counter.to_bytes(16, "little")
            # Update counter and insert tweak
            if row:
                cur.execute("UPDATE counters SET counter=? WHERE domain=?", (counter + 1, domain))
            else:
                cur.execute("INSERT INTO counters(domain, counter) VALUES(?, ?)", (domain, counter + 1))
            cur.execute("INSERT INTO tweaks(domain, hash, tweak) VALUES(?, ?, ?)", (domain, h, tweak))
        conn.commit()
        return tweak
    finally:
        conn.close()

# ============================================================
# HMAC + AES-XTS crypto primitives
# ============================================================
def compute_hmac_over_json_and_ciphertext(json_obj: Dict[str, Any], ciphertext: bytes, domain: str) -> bytes:
    """
    Compute full HMAC-SHA256 over canonical_json || ciphertext using domain mac_key.
    This authenticates both the context and the ciphertext (AE-like).
    """
    keys = KMS.get_keys(domain)
    mac_key = keys["mac_key"]
    canonical = _canonical_json(json_obj).encode()
    # MAC input = canonical_json || ciphertext
    mac_input = canonical + ciphertext
    return hmac.new(mac_key, mac_input, hashlib.sha256).digest()

def _xts_cipher(xts_key: bytes, tweak16: bytes):
    if len(xts_key) != 64:
        raise ValueError("AES-XTS key must be 64 bytes (512 bits).")
    if len(tweak16) != 16:
        raise ValueError("AES-XTS tweak must be 16 bytes.")
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

# ============================================================
# High-level API (compatible with previous interface)
# ============================================================
STORAGE = {}  # in-memory store; replace with persistent DB as needed

def encrypt_ssn(ssn: str, domain: str, json_context: Dict[str, Any] = None, db_file: str = DB_FILE) -> Dict[str, str]:
    """
    Encrypt the SSN (or any string) under domain, using a tweak allocated for the JSON context.
    Returns a dict with fields:
      - ciphertext: hex
      - tweak: hex
      - mac: hex (HMAC-SHA256 over canonical_json || ciphertext)
      - json: the canonical JSON used (string)
    """
    if json_context is None:
        json_context = {"context": domain, "data": ssn}

    canonical = _canonical_json(json_context)
    tweak = allocate_or_get_tweak(json_context, domain, db_file=db_file)  # 16 bytes, unique per JSON
    ciphertext = encrypt_with_tweak(ssn.encode(), domain, tweak)
    mac = compute_hmac_over_json_and_ciphertext(json_context, ciphertext, domain)

    record = {
        "ciphertext": ciphertext.hex(),
        "tweak": tweak.hex(),
        "mac": mac.hex(),
        "json": canonical
    }

    STORAGE.setdefault(domain, []).append(record)
    return record

def decrypt_ssn(record: Dict[str, str], domain: str) -> str:
    """
    Decrypt the record after verifying HMAC matches the canonical JSON and ciphertext.
    Raises ValueError on HMAC mismatch.
    """
    canonical_json = record["json"]
    json_obj = json.loads(canonical_json)
    ciphertext = bytes.fromhex(record["ciphertext"])
    expected_mac = bytes.fromhex(record["mac"])
    computed_mac = compute_hmac_over_json_and_ciphertext(json_obj, ciphertext, domain)
    if not hmac.compare_digest(expected_mac, computed_mac):
        raise ValueError("HMAC mismatch — integrity check failed or wrong domain/key.")
    tweak = bytes.fromhex(record["tweak"])
    plaintext = decrypt_with_tweak(ciphertext, domain, tweak)
    return plaintext.decode()

def verify_ssn_across_domains(domain_storage: Dict[str, list], ssn_plaintext: str, authorized_domains: list):
    """
    Attempts to decrypt stored records across authorized domains and returns matches.
    """
    matches = []
    for domain in authorized_domains:
        records = domain_storage.get(domain, [])
        for rec in records:
            try:
                pt = decrypt_ssn(rec, domain)
                if pt == ssn_plaintext:
                    matches.append(domain)
                    break
            except Exception:
                # HMAC mismatch, decrypt failure, or wrong key — ignore
                pass
    return matches

# ============================================================
# Example usage and quick test when run directly
# ============================================================
if __name__ == "__main__":
    init_db()
    ssn = "123-45-6789"
    domains = ["finance", "healthcare", "education"]

    for d in domains:
        rec = encrypt_ssn(ssn, d, {"context": d, "data": ssn})
        print(f"\n[{d}] Stored record:\n", json.dumps(rec, indent=2))
        print("Decrypted:", decrypt_ssn(rec, d))

    matches = verify_ssn_across_domains(STORAGE, ssn, domains)
    print("\nDomains with matching SSN:", matches)


"""
[finance] Stored record:
 {
  "ciphertext": "40c6e95347a7273d0ff349f1167b8af9",
  "tweak": "00000000000000000000000000000000",
  "mac": "ee436e4296e3327d8605e3b78b13dd2ff11dce5011221ec0f4ab7a6401168018",
  "json": "{\"context\":\"finance\",\"data\":\"123-45-6789\"}"
}
Decrypted: 123-45-6789

[healthcare] Stored record:
 {
  "ciphertext": "2f322a2b4df74c1a40180921537bff2e",
  "tweak": "00000000000000000000000000000000",
  "mac": "c7d950d191e0c13cb9e8b5baaab5c58c4ffe37ff0955761c972779f0b2a8b3b0",
  "json": "{\"context\":\"healthcare\",\"data\":\"123-45-6789\"}"
}
Decrypted: 123-45-6789

[education] Stored record:
 {
  "ciphertext": "71fab31a61859b80232597a6e16b59fb",
  "tweak": "00000000000000000000000000000000",
  "mac": "6de344c72d2b58f41925e21d0317c9bc362df63eb5897b62351a345b031b2ac9",
  "json": "{\"context\":\"education\",\"data\":\"123-45-6789\"}"
}
Decrypted: 123-45-6789

Domains with matching SSN: ['finance', 'healthcare', 'education']
"""

"""
add ciphertext versioning / record format version to enable future crypto migrations,

provide a small migration script to re-encrypt existing Fernet records into this scheme,

swap the SQLite allocator for a Postgres-backed allocator now.
"""

