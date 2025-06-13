use aes_gcm::{Aes256Gcm, aead::{Aead, KeyInit, OsRng}};
use chacha20poly1305::{ChaCha20Poly1305, aead::{Aead as ChaAead, KeyInit as ChaKeyInit}};
use rand::RngCore;
use std::time::Instant;

const NUMBER_OF_MB: usize = 80;
const N: usize = 100;

/// Generates N MB of random data
fn generate_data() -> Vec<u8> {
    let mut data = vec![0u8; 1024 * 1024 * NUMBER_OF_MB];
    rand::thread_rng().fill_bytes(&mut data);
    data
}

/// Benchmarks AES-GCM encryption/decryption performance
fn benchmark_aes(data: &[u8]) -> (f64, f64) {
    let key = Aes256Gcm::generate_key(&mut OsRng);
    let cipher = Aes256Gcm::new(&key);
    let nonce_bytes = rand::random::<[u8; 12]>();
    let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);
    
    // Encrypt
    let start_enc = Instant::now();
    let mut ciphertext = Vec::new();
    for _ in 0..N {
        ciphertext = cipher.encrypt(nonce, data).expect("AES encryption failed");
    }
    let avg_enc = start_enc.elapsed().as_secs_f64() / N as f64;
    
    // Decrypt
    let start_dec = Instant::now();
    for _ in 0..N {
        let _plaintext = cipher.decrypt(nonce, ciphertext.as_ref()).expect("AES decryption failed");
    }
    let avg_dec = start_dec.elapsed().as_secs_f64() / N as f64;
    
    println!("AES-GCM         Encrypt avg: {:.6}s", avg_enc);
    println!("AES-GCM         Decrypt avg: {:.6}s", avg_dec);
    (avg_enc, avg_dec)
}

/// Benchmarks ChaCha20-Poly1305 encryption/decryption performance
fn benchmark_chacha(data: &[u8]) -> (f64, f64) {
    let key = ChaCha20Poly1305::generate_key(&mut OsRng);
    let cipher = ChaCha20Poly1305::new(&key);
    let nonce_bytes = rand::random::<[u8; 12]>();
    let nonce = chacha20poly1305::Nonce::from_slice(&nonce_bytes);
    
    // Encrypt
    let start_enc = Instant::now();
    let mut ciphertext = Vec::new();
    for _ in 0..N {
        ciphertext = cipher.encrypt(nonce, data).expect("ChaCha encryption failed");
    }
    let avg_enc = start_enc.elapsed().as_secs_f64() / N as f64;
    
    // Decrypt
    let start_dec = Instant::now();
    for _ in 0..N {
        let _plaintext = cipher.decrypt(nonce, ciphertext.as_ref()).expect("ChaCha decryption failed");
    }
    let avg_dec = start_dec.elapsed().as_secs_f64() / N as f64;
    
    println!("ChaCha20-Poly1305 Encrypt avg: {:.6}s", avg_enc);
    println!("ChaCha20-Poly1305 Decrypt avg: {:.6}s", avg_dec);
    (avg_enc, avg_dec)
}

fn main() {
    let start_total = Instant::now();
    let data = generate_data();
    
    let (enc_aes, dec_aes) = benchmark_aes(&data);
    let (enc_chacha, dec_chacha) = benchmark_chacha(&data);
    
    let enc_diff = enc_aes - enc_chacha;
    if enc_diff >= 0.0 {
        println!("ChaCha20-Poly1305 is faster at encryption by {:.6}s", enc_diff.abs());
    } else {
        println!("AES-GCM is faster at encryption by {:.6}s", enc_diff.abs());
    }
    
    let dec_diff = dec_aes - dec_chacha;
    if dec_diff >= 0.0 {
        println!("ChaCha20-Poly1305 is faster at decryption by {:.6}s", dec_diff.abs());
    } else {
        println!("AES-GCM is faster at decryption by {:.6}s", dec_diff.abs());
    }
    
    println!("Total benchmark time: {:.6}s", start_total.elapsed().as_secs_f64());
}


/*
 * Memory usage is equivalent: 80MB * 100 encryptions/decryptions each.
 * This avoids writing to disk and uses in-memory benchmarking like your Python version.
 * The rand crate is used to generate random keys, nonces, and data.
 * The aes-gcm and chacha20poly1305 crates implement AEAD (Authenticated Encryption with Associated Data) just like Python's cryptography library.
 * 
 * ✅ Build and Run: ⚡ Use --release to get optimized benchmark results (important for timing comparisons).
 *          make run    // cargo run --release
 *          make clean
 * 
 * 📦 Optional: Clear build cache between runs
 * To ensure you're always testing fresh builds (for consistency):
 *          cargo clean && cargo run --release
 * 
 * 
 */