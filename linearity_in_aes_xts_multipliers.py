import numpy as np
import matplotlib.pyplot as plt
from collections import defaultdict
import random

class GF2_128:
    """
    Simplified GF(2^128) field operations for AES-XTS
    Uses the irreducible polynomial x^128 + x^7 + x^2 + x + 1
    """
    @staticmethod
    def multiply(a, b):
        """Multiply two elements in GF(2^128) - simplified for demonstration"""
        result = 0

        for i in range(128):
            if b & 1:
                result ^= a
            b >>= 1
            # Check if high bit is set
            if a & (1 << 127):
                a = (a << 1) ^ 0x87  # XTS reduction polynomial
            else:
                a <<= 1
            a &= ((1 << 128) - 1)  # Keep within 128 bits

        return result

def generate_sequential_tweaks(initial_tweak, count):
    """Generate XTS-style sequential tweaks by multiplying by 2 (α) in GF(2^128)"""
    alpha = 2
    tweaks = []
    current = initial_tweak

    for i in range(count):
        tweaks.append(current)
        current = GF2_128.multiply(current, alpha)

    return tweaks

def analyze_linear_dependence(tweaks):
    """Look for actual linear relationships that emerge"""
    dependencies = []

    # Check for patterns in consecutive differences
    diffs = []
    for i in range(1, min(10000, len(tweaks))):  # Sample first 10k
        diff = tweaks[i] ^ tweaks[i-1]  # XOR difference
        diffs.append(diff)

    # Count frequency of differences
    diff_counts = defaultdict(int)
    for diff in diffs:
        # Look at just lower 32 bits for patterns
        lower_diff = diff & 0xFFFFFFFF
        diff_counts[lower_diff] += 1

    # Find most common differences
    sorted_diffs = sorted(diff_counts.items(), key=lambda x: x[1], reverse=True)

    return sorted_diffs[:10], diffs

def find_cycle_length(tweaks):
    """Try to find if there's a detectable cycle"""
    # For demonstration, look at just the lower bits
    seen = {}
    for i, tweak in enumerate(tweaks[:100000]):  # Check first 100k
        lower_bits = tweak & 0xFFFF  # Just lower 16 bits
        if lower_bits in seen:
            cycle_length = i - seen[lower_bits]
            return cycle_length, seen[lower_bits], i
        seen[lower_bits] = i
    return None, None, None

def hamming_weight_analysis(tweaks):
    """Analyze Hamming weights (number of 1s) - should be random around 64"""
    weights = []
    for tweak in tweaks[:10000]:  # Sample first 10k
        weight = bin(tweak).count('1')
        weights.append(weight)
    return weights

def main():
    print("AES-XTS GF(2^128) Linearity Analysis - Improved Version")
    print("=" * 60)

    # Use a simple initial tweak to make patterns more visible
    initial_tweak = 1  # Start simple to see patterns emerge
    print(f"Initial tweak: 0x{initial_tweak:032x}")

    # Generate more tweaks to see patterns
    print("\nGenerating tweak sequence...")
    num_tweaks = 100000  # More tweaks to see patterns
    tweaks = generate_sequential_tweaks(initial_tweak, num_tweaks)

    # Analyze linear relationships
    print("Analyzing linear dependencies...")
    common_diffs, all_diffs = analyze_linear_dependence(tweaks)

    # Look for cycles
    print("Searching for cycles...")
    cycle_len, cycle_start, cycle_end = find_cycle_length(tweaks)

    # Hamming weight analysis
    print("Analyzing Hamming weights...")
    hamming_weights = hamming_weight_analysis(tweaks)

    # Create better visualizations
    fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(15, 12))

    # Plot 1: First few tweaks to show the doubling pattern
    first_tweaks = tweaks[:20]
    ax1.semilogy(range(len(first_tweaks)), first_tweaks, 'bo-', markersize=8)
    ax1.set_title('First 20 Tweaks (Note the Doubling Pattern)')
    ax1.set_xlabel('Tweak Index')
    ax1.set_ylabel('Tweak Value (log scale)')
    ax1.grid(True, alpha=0.3)

    # Plot 2: XOR differences between consecutive tweaks
    diff_sample = [d & 0xFFFFFFFF for d in all_diffs[:1000]]  # Lower 32 bits only
    ax2.plot(diff_sample, 'r-', alpha=0.7, linewidth=0.5)
    ax2.set_title('XOR Differences Between Consecutive Tweaks (Lower 32 bits)')
    ax2.set_xlabel('Difference Index')
    ax2.set_ylabel('XOR Difference Value')
    ax2.grid(True, alpha=0.3)

    # Plot 3: Hamming weight distribution
    ax3.hist(hamming_weights, bins=30, alpha=0.7, color='green', edgecolor='black')
    ax3.axvline(x=64, color='red', linestyle='--', linewidth=2, label='Expected (64)')
    ax3.set_title('Hamming Weight Distribution')
    ax3.set_xlabel('Number of 1-bits')
    ax3.set_ylabel('Frequency')
    ax3.legend()
    ax3.grid(True, alpha=0.3)

    # Plot 4: Lower bits over time to show periodicity
    # Take every 100th tweak to see longer-term patterns
    sample_indices = range(0, min(50000, len(tweaks)), 100)
    lower_16_bits = [(tweaks[i] & 0xFFFF) for i in sample_indices]
    ax4.plot(sample_indices, lower_16_bits, 'b-', alpha=0.8, linewidth=1)
    ax4.set_title('Lower 16 Bits Over Time (Every 100th Tweak)')
    ax4.set_xlabel('Tweak Index')
    ax4.set_ylabel('Lower 16 Bits Value')
    ax4.grid(True, alpha=0.3)

    plt.tight_layout()
    plt.show()

    # Print detailed analysis
    print(f"\nDetailed Analysis Results:")
    print(f"=" * 40)
    print(f"Total tweaks generated: {len(tweaks):,}")

    print(f"\nLinear Pattern Evidence:")
    print(f"1. DOUBLING PATTERN: Each tweak = previous × 2 (mod irreducible polynomial)")
    print(f"   - First few tweaks: {[hex(t) for t in tweaks[:5]]}")

    print(f"\n2. XOR DIFFERENCE PATTERNS:")
    if common_diffs:
        print(f"   Most common XOR differences (lower 32 bits):")
        for diff_val, count in common_diffs[:5]:
            print(f"   - 0x{diff_val:08x}: appears {count:,} times")

    if cycle_len:
        print(f"\n3. CYCLE DETECTION:")
        print(f"   - Found cycle in lower 16 bits: length {cycle_len:,}")
        print(f"   - First occurrence at index {cycle_start:,}")
        print(f"   - Repeated at index {cycle_end:,}")
    else:
        print(f"\n3. CYCLE DETECTION:")
        print(f"   - No short cycles found in first 100k tweaks")
        print(f"   - But cycles WILL appear eventually (2^16 = 65,536 max for 16-bit)")

    print(f"\n4. HAMMING WEIGHT ANALYSIS:")
    hw_mean = np.mean(hamming_weights)
    hw_std = np.std(hamming_weights)
    print(f"   - Mean Hamming weight: {hw_mean:.2f} (should be ~64)")
    print(f"   - Standard deviation: {hw_std:.2f}")
    if abs(hw_mean - 64) > 2:
        print(f"   - WARNING: Significant deviation from expected 64!")

    print(f"\n5. THE LINEARITY PROBLEM:")
    print(f"   - Each tweak is EXACTLY 2 × previous tweak in GF(2^128)")
    print(f"   - This creates a completely deterministic sequence")
    print(f"   - After 2^128 operations, the sequence repeats exactly")
    print(f"   - Cryptanalysts can exploit this predictability")

    print(f"\nWhy XTS Limits Operations:")
    print(f"- The multiplication by 2 creates a linear recurrence")
    print(f"- Patterns become exploitable well before 2^128 operations")
    print(f"- XTS limits to ~2^20 operations to stay in 'safe zone'")
    print(f"- This prevents practical cryptanalytic attacks")

    # Demonstrate the exact linearity
    print(f"\nDemonstrating Perfect Linearity:")
    print("If you know any tweak T_i, you can compute all future tweaks:")
    demo_start = 1000
    predicted = GF2_128.multiply(tweaks[demo_start], 2)  # Predict next
    actual = tweaks[demo_start + 1]
    print(f"T_{demo_start} = 0x{tweaks[demo_start]:032x}")
    print(f"T_{demo_start+1} predicted = 0x{predicted:032x}")
    print(f"T_{demo_start+1} actual    = 0x{actual:032x}")
    print(f"Match: {predicted == actual}")

if __name__ == "__main__":
    main()

"""
AES-XTS GF(2^128) Linearity Analysis - Improved Version
============================================================
Initial tweak: 0x00000000000000000000000000000001

Generating tweak sequence...
Analyzing linear dependencies...
Searching for cycles...
Analyzing Hamming weights...


Detailed Analysis Results:
========================================
Total tweaks generated: 100,000

Linear Pattern Evidence:
1. DOUBLING PATTERN: Each tweak = previous × 2 (mod irreducible polynomial)
   - First few tweaks: ['0x1', '0x2', '0x4', '0x8', '0x10']

2. XOR DIFFERENCE PATTERNS:
   Most common XOR differences (lower 32 bits):
   - 0x00000000: appears 961 times
   - 0x00000624: appears 38 times
   - 0x00000c48: appears 38 times
   - 0x00000312: appears 36 times
   - 0x00000189: appears 34 times

3. CYCLE DETECTION:
   - Found cycle in lower 16 bits: length 1
   - First occurrence at index 16
   - Repeated at index 17

4. HAMMING WEIGHT ANALYSIS:
   - Mean Hamming weight: 40.32 (should be ~64)
   - Standard deviation: 20.07
   - WARNING: Significant deviation from expected 64!

5. THE LINEARITY PROBLEM:
   - Each tweak is EXACTLY 2 × previous tweak in GF(2^128)
   - This creates a completely deterministic sequence
   - After 2^128 operations, the sequence repeats exactly
   - Cryptanalysts can exploit this predictability

Why XTS Limits Operations:
- The multiplication by 2 creates a linear recurrence
- Patterns become exploitable well before 2^128 operations
- XTS limits to ~2^20 operations to stay in 'safe zone'
- This prevents practical cryptanalytic attacks

Demonstrating Perfect Linearity:
If you know any tweak T_i, you can compute all future tweaks:
T_1000 = 0xf78f5b00000000000000000100000079
T_1001 predicted = 0xef1eb600000000000000000200000075
T_1001 actual    = 0xef1eb600000000000000000200000075
Match: True
"""    