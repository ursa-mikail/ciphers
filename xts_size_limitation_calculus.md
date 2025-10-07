## 2⁻⁸⁸ threshold 

The 2⁻⁸⁸ threshold was the design target probability that the XTS designers used to define a safe maximum data-unit size (2²⁰ blocks = 16 MiB).

It ensures each sector’s internal structure contributes no more than a 2⁻⁸⁸ degradation to AES-128’s overall 128-bit security.

| Quantity           | Symbol                       | Value                            | Rationale           |
| ------------------ | ---------------------------- | -------------------------------- | ------------------- |
| AES block size     | (b)                          | 128 bits                         | fixed by AES        |
| Target bound       | (n^2 / 2^{128} ≤ 2^{-88})    | chosen to keep failure < 3×10⁻²⁷ |                     |
| Implied max blocks | (n_{\max})                   | (2^{20})                         | from the inequality |
| Max data-unit size | (16 \text{MiB})              | (2^{20} × 16 \text{B})           |                     |
| Margin vs AES-128  | 40 bits                      | (128 – 88 = 40) bit gap          |                     |
| Practical meaning  | residual advantage ≈ 3×10⁻²⁷ | “cryptographically negligible”   |                     |


## 🔹 Why 2⁻⁸⁸ instead of, say, 2⁻⁶⁴ or 2⁻⁹⁶?
2⁻⁶⁴

Too loose — a 64-bit collision bound is comparable to a CRC32-style accidental-collision space, and no longer “cryptographically negligible” if you encrypt trillions of sectors.

2⁻⁹⁶ or smaller

Overly strict — would force smaller data-unit sizes (≤ 2¹⁶ blocks ≈ 1 MiB), which complicates implementations with negligible real gain.

2⁻⁸⁸

Sweet spot:

- Still vastly beyond any feasible attack (≈ 3×10⁻²⁷ chance).
- Matches round binary exponents (difference of 40 bits from 128).
- Allows 16 MiB maximum sector and simple hardware design.
- It’s therefore a design-level engineering constant, not a law of nature.

## 16 MiB maximum sector


--- 


[\ 2^20 \]