| Feature / Aspect           | **AES-GCM**                                                                 | **AES-XTS**                                                                 |
|-----------------------------|-----------------------------------------------------------------------------|------------------------------------------------------------------------------|
| **NIST Approval**           | NIST-approved (SP 800-38D). Widely standardized for authenticated encryption. | NIST-approved for storage encryption (SP 800-38E). Specifically designed for disk/file encryption. |
| **Authentication**          | Built-in authentication tag (integrity + authenticity guaranteed). Authenticated Encryption with Associated Data (AEAD). Provides confidentiality + integrity.         | No authentication; must combine with HMAC/MAC for tamper protection. Tweakable block cipher mode. Provides confidentiality, but **not integrity** (no authentication). |
| **Parallelism**             | Parallelizable (encrypt/decrypt + GHASH). Suited for multicore CPUs.       | Highly parallelizable (each sector independent). Well-suited for random-access storage. |
| **Encryption Size Limit**   | Limited to ~64 GiB per key/IV pair (2^39−256 bits).                        | Extremely large: up to ~2^120 blocks (virtually unlimited). |
| **Random Access**           | Poor fit — requires sequential nonce management. Random access risks nonce reuse. | Excellent fit — each sector/block encrypted independently using tweak = sector number. |
| **Performance**             | Very fast on AES-NI capable CPUs. Authentication adds overhead.             | Very fast on AES-NI CPUs. No authentication overhead, simpler pipeline. |
| **Error Propagation**       | Authentication failure if any ciphertext block modified; whole file may be unreadable. | Corruption limited to the affected sector (usually 16 or 32 bytes). Rest remains usable. |
| **Integrity Protection**    | Built-in. Detects even single-bit modifications.                           | None. Attackers can flip bits in ciphertext undetected. |
| **Padding/Block Handling**  | Handles arbitrary-length plaintext (via counter mode + tag).               | Requires ciphertext stealing (CTS) for non-multiple-of-block-size data. |
| **Implementation Notes**    | IV/nonce must never repeat for same key — reuse breaks security.            | Requires 2 AES keys internally (K1, K2). Implementations must carefully manage tweaks. |
| **Common Use Cases**        | Secure file formats (archives, databases), cloud object storage, TLS/IPsec. | Full-disk encryption, encrypted file systems, virtual machine disks. |
| **Recommended Usage**       | Use when you need **confidentiality + authenticity** (e.g., tamper-proof file encryption, backups, secure messaging). | Use when you need **fast random-access encryption without authentication** (e.g., full-disk encryption, live mounted drives, storage media). |

