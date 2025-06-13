# aes-gcm_vs_chacha20-poly1305
## Caveat(s)
Intermediate Observation:


| Language / Library | Faster Cipher(s)                            | Slower Cipher(s)                            |
|--------------------|---------------------------------------------|---------------------------------------------|
| OpenSSL            | AES-256-GCM                                 | ChaCha20-Poly1305                           |
| Python             | ChaCha20-Poly1305                           | AES-256-GCM                                 |
| Go (Golang)        | AES-256-GCM                                 | ChaCha20-Poly1305                           |
| Rust               | ChaCha20-Poly1305<br>AES-SIV                | AES-256-GCM<br>XChaCha20-Poly1305           |


General claims

| Cipher            | Speed (Encrypt) | Speed (Decrypt) | Notes                          |
| ----------------- | --------------- | --------------- | ------------------------------ |
| AES-256-GCM       | Fast w/ AES-NI  | Fast            | Slower on systems w/o AES-NI   |
| ChaCha20-Poly1305 | Uniformly fast  | Uniformly fast  | Great on mobile, constant-time |

AES-GCM is faster on CPUs with AES-NI.
ChaCha20-Poly1305 outperforms on ARM or systems lacking hardware acceleration. However, this is not the case for golang.
Both are secure and standardized in TLS 1.3.

 crypto/aes
 golang.org/x/crypto/chacha20poly1305

 Benchmark Poly1305-ChaCha20 (PolyCha) vs AES-GCM using openssl, python, and golang. Each test will encrypt a fixed-size message (e.g., 1 MB), and we'll measure time/speed.

🔧 Parameters for Benchmark
Data size: 1 MB (1048576 bytes)
Repetitions: 100 iterations (adjustable)

``` python
AES-GCM Encrypt avg: 0.103866s
AES-GCM Decrypt avg: 0.108257s
ChaCha20-Poly1305 Encrypt avg: 0.136823s
ChaCha20-Poly1305 Decrypt avg: 0.136730s
ChaCha20-Poly1305 is faster than AES-GCM by : 0.032957s
ChaCha20-Poly1305 is faster than AES-GCM by : 0.028473s
Total time: 48.602654s
```

``` golang
% go run main.go
AES-GCM Encrypt avg: 0.017811s
AES-GCM Decrypt avg: 0.015735s
ChaCha20-Poly1305 Encrypt avg: 0.096102s
ChaCha20-Poly1305 Decrypt avg: 0.096312s
AES-GCM is faster than ChaCha20-Poly1305 by: 0.078291s
AES-GCM is faster than ChaCha20-Poly1305 by: 0.080577s
Total time: 22.657542s
```

``` openssl
 Outputs time per operation for block sizes (16, 64, 256, 1024, 8192 bytes).
# Use openssl version to ensure ≥1.1.0 for chacha20-poly1305 support.
!openssl speed -evp aes-256-gcm
!openssl speed -evp chacha20-poly1305

Doing AES-256-GCM for 3s on 16 size blocks: 28853681 AES-256-GCM's in 2.45s
Doing AES-256-GCM for 3s on 64 size blocks: 12023583 AES-256-GCM's in 1.67s
Doing AES-256-GCM for 3s on 256 size blocks: 11448584 AES-256-GCM's in 2.76s
Doing AES-256-GCM for 3s on 1024 size blocks: 4210453 AES-256-GCM's in 2.72s
Doing AES-256-GCM for 3s on 8192 size blocks: 691348 AES-256-GCM's in 2.84s
Doing AES-256-GCM for 3s on 16384 size blocks: 246924 AES-256-GCM's in 2.08s
version: 3.0.2
built on: Wed Feb  5 13:19:41 2025 UTC
options: bn(64,64)
compiler: gcc -fPIC -pthread -m64 -Wa,--noexecstack -Wall -Wa,--noexecstack -g -O2 -ffile-prefix-map=/build/openssl-rEtvJl/openssl-3.0.2=. -flto=auto -ffat-lto-objects -flto=auto -ffat-lto-objects -fstack-protector-strong -Wformat -Werror=format-security -DOPENSSL_TLS_SECURITY_LEVEL=2 -DOPENSSL_USE_NODELETE -DL_ENDIAN -DOPENSSL_PIC -DOPENSSL_BUILDING_OPENSSL -DNDEBUG -Wdate-time -D_FORTIFY_SOURCE=2
CPUINFO: OPENSSL_ia32cap=0xfefa32035f8bffff:0x1c2ffb
The 'numbers' are in 1000s of bytes per second processed.
type             16 bytes     64 bytes    256 bytes   1024 bytes   8192 bytes  16384 bytes
AES-256-GCM     188432.20k   460784.02k  1061897.65k  1585111.72k  1994198.17k  1945001.35k
Doing ChaCha20-Poly1305 for 3s on 16 size blocks: 19953740 ChaCha20-Poly1305's in 2.41s
Doing ChaCha20-Poly1305 for 3s on 64 size blocks: 13241661 ChaCha20-Poly1305's in 2.86s
Doing ChaCha20-Poly1305 for 3s on 256 size blocks: 6051148 ChaCha20-Poly1305's in 2.83s
Doing ChaCha20-Poly1305 for 3s on 1024 size blocks: 2144561 ChaCha20-Poly1305's in 2.13s
Doing ChaCha20-Poly1305 for 3s on 8192 size blocks: 255720 ChaCha20-Poly1305's in 1.86s
Doing ChaCha20-Poly1305 for 3s on 16384 size blocks: 266451 ChaCha20-Poly1305's in 2.96s
version: 3.0.2
built on: Wed Feb  5 13:19:41 2025 UTC
options: bn(64,64)
compiler: gcc -fPIC -pthread -m64 -Wa,--noexecstack -Wall -Wa,--noexecstack -g -O2 -ffile-prefix-map=/build/openssl-rEtvJl/openssl-3.0.2=. -flto=auto -ffat-lto-objects -flto=auto -ffat-lto-objects -fstack-protector-strong -Wformat -Werror=format-security -DOPENSSL_TLS_SECURITY_LEVEL=2 -DOPENSSL_USE_NODELETE -DL_ENDIAN -DOPENSSL_PIC -DOPENSSL_BUILDING_OPENSSL -DNDEBUG -Wdate-time -D_FORTIFY_SOURCE=2
CPUINFO: OPENSSL_ia32cap=0xfefa32035f8bffff:0x1c2ffb
The 'numbers' are in 1000s of bytes per second processed.
type             16 bytes     64 bytes    256 bytes   1024 bytes   8192 bytes  16384 bytes
ChaCha20-Poly1305   132472.96k   296316.89k   547383.00k  1031000.22k  1126267.87k  1474842.29k
```

### Note: 
- Fixed nonce type annotations: Instead of using generic Nonce types, explicitly use aes_gcm::Nonce and chacha20poly1305::Nonce to help the compiler infer the correct types.
- Separated nonce generation: Created nonce_bytes first, then passed to from_slice() to avoid type inference issues.
- Deter import conflicts: Renamed the ChaCha20 trait imports to avoid conflicts with AES-GCM imports (ChaAead, ChaKeyInit).
- Deter syntax errors: Replaced the invalid let * syntax with proper variable names like _plaintext.
- Removed unused imports: Cleaned up the unused KeyInit and Aead imports that were causing warnings.
```
cargo update
cargo run --release
```

``` rust
% make run 

AES-GCM         Encrypt avg: 0.642772s
AES-GCM         Decrypt avg: 0.647063s
ChaCha20-Poly1305 Encrypt avg: 0.320332s
ChaCha20-Poly1305 Decrypt avg: 0.319603s
ChaCha20-Poly1305 is faster at encryption by 0.322441s
ChaCha20-Poly1305 is faster at decryption by 0.327460s
Total benchmark time: 193.111705s

% make run 
cargo run --release --manifest-path bench/Cargo.toml
AES-SIV Encrypt avg: 0.134099s
AES-SIV Decrypt avg: 0.133664s
XChaCha20-Poly1305 Encrypt avg: 0.321946s
XChaCha20-Poly1305 Decrypt avg: 0.319210s
AES-SIV is faster at encryption by 0.187847s
AES-SIV is faster at decryption by 0.185546s
Total benchmark time: 91.023153s

```