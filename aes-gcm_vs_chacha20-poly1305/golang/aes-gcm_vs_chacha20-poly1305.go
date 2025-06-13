package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	numberOfMB = 80
	N          = 100
)

func generateRandomBytes(n int) []byte {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return b
}

func benchmarkAESGCM(data []byte) (float64, float64) {
	key := generateRandomBytes(32)
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	nonce := generateRandomBytes(12)

	var ct []byte

	startEnc := time.Now()
	for i := 0; i < N; i++ {
		ct = aesgcm.Seal(nil, nonce, data, nil)
	}
	endEnc := time.Now()

	startDec := time.Now()
	for i := 0; i < N; i++ {
		_, err := aesgcm.Open(nil, nonce, ct, nil)
		if err != nil {
			panic(err)
		}
	}
	endDec := time.Now()

	avgEnc := endEnc.Sub(startEnc).Seconds() / float64(N)
	avgDec := endDec.Sub(startDec).Seconds() / float64(N)

	fmt.Printf("AES-GCM Encrypt avg: %.6fs\n", avgEnc)
	fmt.Printf("AES-GCM Decrypt avg: %.6fs\n", avgDec)

	return avgEnc, avgDec
}

func benchmarkChaCha(data []byte) (float64, float64) {
	key := generateRandomBytes(32)
	chacha, err := chacha20poly1305.New(key)
	if err != nil {
		panic(err)
	}
	nonce := generateRandomBytes(chacha.NonceSize())

	var ct []byte

	startEnc := time.Now()
	for i := 0; i < N; i++ {
		ct = chacha.Seal(nil, nonce, data, nil)
	}
	endEnc := time.Now()

	startDec := time.Now()
	for i := 0; i < N; i++ {
		_, err := chacha.Open(nil, nonce, ct, nil)
		if err != nil {
			panic(err)
		}
	}
	endDec := time.Now()

	avgEnc := endEnc.Sub(startEnc).Seconds() / float64(N)
	avgDec := endDec.Sub(startDec).Seconds() / float64(N)

	fmt.Printf("ChaCha20-Poly1305 Encrypt avg: %.6fs\n", avgEnc)
	fmt.Printf("ChaCha20-Poly1305 Decrypt avg: %.6fs\n", avgDec)

	return avgEnc, avgDec
}

func main() {
	start := time.Now()

	data := generateRandomBytes(numberOfMB * 1024 * 1024)

	encAES, decAES := benchmarkAESGCM(data)
	encCha, decCha := benchmarkChaCha(data)

	diffEnc := encAES - encCha
	if diffEnc >= 0 {
		fmt.Printf("ChaCha20-Poly1305 is faster than AES-GCM by: %.6fs\n", diffEnc)
	} else {
		fmt.Printf("AES-GCM is faster than ChaCha20-Poly1305 by: %.6fs\n", -diffEnc)
	}

	diffDec := decAES - decCha
	if diffDec >= 0 {
		fmt.Printf("ChaCha20-Poly1305 is faster than AES-GCM by: %.6fs\n", diffDec)
	} else {
		fmt.Printf("AES-GCM is faster than ChaCha20-Poly1305 by: %.6fs\n", -diffDec)
	}

	total := time.Since(start).Seconds()
	fmt.Printf("Total time: %.6fs\n", total)
}

/**
% go run main.go
AES-GCM Encrypt avg: 0.017811s
AES-GCM Decrypt avg: 0.015735s
ChaCha20-Poly1305 Encrypt avg: 0.096102s
ChaCha20-Poly1305 Decrypt avg: 0.096312s
AES-GCM is faster than ChaCha20-Poly1305 by: 0.078291s
AES-GCM is faster than ChaCha20-Poly1305 by: 0.080577s
Total time: 22.657542s


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
Operations: Keygen + Encrypt + Decrypt
*/
