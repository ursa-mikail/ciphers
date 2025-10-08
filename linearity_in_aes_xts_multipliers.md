# linearity_in_aes_xts_multipliers

![linearity_in_aes_xts_multipliers](linearity_in_aes_xts_multipliers.png)

### Chart 1: First 20 Tweaks (Doubling Pattern)

What you'll see: A perfect exponential curve - each point is exactly double the previous one.
The linearity: This is the core problem! Each tweak is mathematically predictable from the previous one.

### Chart 2: XOR Differences Between Consecutive Tweaks

What you'll see: Structured patterns, not random noise.
The problem: In truly random data, these differences would be chaotic. The patterns show mathematical relationships.

### Chart 3: Hamming Weight Distribution

What you'll see: The distribution might be skewed from the expected center at 64.
The linearity: Random 128-bit numbers should have about 64 ones. Deviations show the sequence isn't truly random.

### Chart 4: Lower 16 Bits Over Time

What you'll see: Repeating cycles and patterns.
The critical issue: These patterns repeat! An attacker can predict future values.

### The Key Revelation:
The perfect linearity is now visible because:

Each tweak = previous tweak × 2 (in GF(2^128))
This creates a completely deterministic sequence
The "randomness" is an illusion - it's actually pure math

### Why This Matters for XTS:

1. Predictability: If an attacker learns one tweak, they can compute all future tweaks
2. Cycles: The sequence will eventually repeat (after 2^128 steps, but patterns emerge much sooner)
3. Exploitation: Cryptanalysts can use these linear relationships to attack the encryption

The XTS specification limits operations to ~1 million blocks precisely because this mathematical linearity becomes exploitable at scale, even though the individual operations look "random" to casual observation.

