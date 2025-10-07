## 2⁻⁸⁸ threshold 

The 2⁻⁸⁸ threshold (2⁻⁸⁸ was chosen as the safety threshold in AES-XTS (IEEE P1619 / NIST SP 800-38E)) was the design target probability that the XTS designers used to define a safe maximum data-unit size (2²⁰ blocks = 16 MiB).

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

### Deciding “how small is small enough”

When the P1619 working group and NIST’s SP 800-38E editors formalized XTS, they needed a bound small enough that even in worst-case use, the total risk would remain cryptographically negligible.

They targeted:

residual probability ≤ $\ 2^{-88} \$

It’s 40 bits below AES-128’s baseline 128-bit strength, which is:

- so small it’s astronomically unlikely in practice, yet
- not so extreme that it prevents practical 20-bit counters and 16 MiB sectors.

Formally, it means:

> even if you encrypt the largest allowed sector (16 MiB, = 2²⁰ blocks),
> the distinguishing advantage contributed by intra-sector collisions is ≤ 2⁻⁸⁸.

That bound keeps XTS’s total security level effectively at ≈ 128 bits – 0 bits for realistic use.

---

## 16 MiB maximum sector

### Numeric reasoning behind the 40-bit margin

They wanted a nice round power-of-2 number of blocks per sector that would:

> make hardware counters simple (20 bits);
> keep $\ \frac{n^2}{2^128} \$ ≤ 2⁻⁸⁸.

Solve:

$\ \frac{n^2}{2^128} \$ = 2⁻⁸⁸ => n = $\ 2^{20} \$

That gives $\ 2^{20} \$ blocks × 16 bytes = 16 MiB.
So 16 MiB naturally falls out of that $\ 2^{-88} \$ target.
In other words, the bound 2⁻⁸⁸ caused the 16 MiB cap, not the other way around.


--- 
## Structure of the XTS security proof

$\ Advantage <= \frac{q^2}{2^k} + \frac{n^2}{2^b} \$

| Symbol | Meaning                                        |
| ------ | ---------------------------------------------- |
| (k)    | AES key size (128 bits)                        |
| (b)    | AES block size (128 bits)                      |
| (q)    | total number of AES invocations under one key  |
| (n)    | number of blocks within one data unit (sector) |


The second term, $\ \frac{n^2}{2^128} \$ , measures the probability that two blocks within the same data unit collide in whitening value or otherwise reveal a structural relation.

---

$\ 2^{20} \$



