use aes_siv::{Aes256SivAead, aead::{Aead as SivAead, KeyInit as SivKeyInit}};
use chacha20poly1305::{XChaCha20Poly1305, aead::{Aead, KeyInit, OsRng}};
use rand::RngCore;
use std::time::Instant;

const NUMBER_OF_MB: usize = 80;
const N: usize = 100;

fn generate_data() -> Vec<u8> {
    let mut data = vec![0u8; 1024 * 1024 * NUMBER_OF_MB];
    rand::thread_rng().fill_bytes(&mut data);
    data
}

fn benchmark_aes_siv(data: &[u8]) -> (f64, f64) {
    // Generate a random 512-bit (64-byte) key for AES-256-SIV
    let mut key_bytes = [0u8; 64];
    rand::thread_rng().fill_bytes(&mut key_bytes);
    let key: aes_siv::Key<Aes256SivAead> = key_bytes.into();
    let cipher = Aes256SivAead::new(&key);
    
    // AES-SIV uses a 128-bit (16-byte) nonce
    let nonce_bytes = rand::random::<[u8; 16]>();
    let nonce = aes_siv::Nonce::try_from(nonce_bytes.as_slice()).expect("Invalid nonce length");
    
    // Encrypt
    let start_enc = Instant::now();
    let mut ciphertext = Vec::new();
    for _ in 0..N {
        ciphertext = cipher.encrypt(&nonce, data).expect("AES-SIV encryption failed");
    }
    let avg_enc = start_enc.elapsed().as_secs_f64() / N as f64;
    
    // Decrypt
    let start_dec = Instant::now();
    for _ in 0..N {
        let _plaintext = cipher.decrypt(&nonce, ciphertext.as_slice()).expect("AES-SIV decryption failed");
    }
    let avg_dec = start_dec.elapsed().as_secs_f64() / N as f64;
    
    println!("AES-SIV Encrypt avg: {:.6}s", avg_enc);
    println!("AES-SIV Decrypt avg: {:.6}s", avg_dec);
    (avg_enc, avg_dec)
}

fn benchmark_xchacha(data: &[u8]) -> (f64, f64) {
    let key = XChaCha20Poly1305::generate_key(&mut OsRng);
    let cipher = XChaCha20Poly1305::new(&key);
    
    // XChaCha20-Poly1305 uses a 192-bit (24-byte) nonce
    let nonce_bytes = rand::random::<[u8; 24]>();
    let nonce = chacha20poly1305::XNonce::from_slice(&nonce_bytes);
    
    // Encrypt
    let start_enc = Instant::now();
    let mut ciphertext = Vec::new();
    for _ in 0..N {
        ciphertext = cipher.encrypt(nonce, data).expect("XChaCha20 encryption failed");
    }
    let avg_enc = start_enc.elapsed().as_secs_f64() / N as f64;
    
    // Decrypt
    let start_dec = Instant::now();
    for _ in 0..N {
        let _plaintext = cipher.decrypt(nonce, ciphertext.as_slice()).expect("XChaCha20 decryption failed");
    }
    let avg_dec = start_dec.elapsed().as_secs_f64() / N as f64;
    
    println!("XChaCha20-Poly1305 Encrypt avg: {:.6}s", avg_enc);
    println!("XChaCha20-Poly1305 Decrypt avg: {:.6}s", avg_dec);
    (avg_enc, avg_dec)
}

fn main() {
    let start_total = Instant::now();
    let data = generate_data();
    
    let (enc_siv, dec_siv) = benchmark_aes_siv(&data);
    let (enc_xchacha, dec_xchacha) = benchmark_xchacha(&data);
    
    let enc_diff = enc_siv - enc_xchacha;
    if enc_diff >= 0.0 {
        println!("XChaCha20-Poly1305 is faster at encryption by {:.6}s", enc_diff.abs());
    } else {
        println!("AES-SIV is faster at encryption by {:.6}s", enc_diff.abs());
    }
    
    let dec_diff = dec_siv - dec_xchacha;
    if dec_diff >= 0.0 {
        println!("XChaCha20-Poly1305 is faster at decryption by {:.6}s", dec_diff.abs());
    } else {
        println!("AES-SIV is faster at decryption by {:.6}s", dec_diff.abs());
    }
    
    println!("Total benchmark time: {:.6}s", start_total.elapsed().as_secs_f64());
}