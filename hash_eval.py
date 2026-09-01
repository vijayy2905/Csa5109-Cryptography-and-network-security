"""
hash_eval.py
Evaluates candidate cryptographic hash algorithms on the sample EHR data:
  - MD5      (legacy / broken -- included ONLY as a negative baseline)
  - SHA-1    (legacy / deprecated -- included ONLY as a negative baseline)
  - SHA-256  (current industry baseline, FIPS 180-4)
  - SHA-512  (FIPS 180-4, larger output / margin)
  - SHA3-256 (FIPS 202, Keccak sponge construction, structurally distinct
              from SHA-2 -- included as a defense-in-diversity comparator)
  - BLAKE2b  (RFC 7693, high-performance modern design)

For each algorithm we report:
  1. digest (hex)
  2. digest size (bits)
  3. computation time over N iterations (µs/op) on the sample record
  4. avalanche effect: % of output bits that flip when ONE character of the
     input is changed (a well-designed hash should flip ~50%)
"""

import hashlib
import time
from ehr_data import canonical_json, sample_ehr_record

ALGORITHMS = {
    "MD5": lambda: hashlib.md5(),
    "SHA-1": lambda: hashlib.sha1(),
    "SHA-256": lambda: hashlib.sha256(),
    "SHA-512": lambda: hashlib.sha512(),
    "SHA3-256": lambda: hashlib.sha3_256(),
    "BLAKE2b-256": lambda: hashlib.blake2b(digest_size=32),
}

N_ITER = 20000


def hex_to_bits(h: str) -> str:
    return bin(int(h, 16))[2:].zfill(len(h) * 4)


def hamming_distance(a: str, b: str) -> int:
    return sum(c1 != c2 for c1, c2 in zip(a, b))


def digest_of(algo_name: str, data: bytes) -> str:
    h = ALGORITHMS[algo_name]()
    h.update(data)
    return h.hexdigest()


def time_algorithm(algo_name: str, data: bytes, n=N_ITER) -> float:
    start = time.perf_counter()
    for _ in range(n):
        h = ALGORITHMS[algo_name]()
        h.update(data)
        h.digest()
    elapsed = time.perf_counter() - start
    return (elapsed / n) * 1e6  # microseconds/op


def avalanche_effect(algo_name: str, data: bytes) -> float:
    """Flip a single bit of the LAST byte of the plaintext and measure the
    fraction of output digest bits that change."""
    original_digest = digest_of(algo_name, data)
    mutated = bytearray(data)
    mutated[-1] ^= 0x01  # flip the least-significant bit of the last byte
    mutated_digest = digest_of(algo_name, bytes(mutated))

    bits_a = hex_to_bits(original_digest)
    bits_b = hex_to_bits(mutated_digest)
    flips = hamming_distance(bits_a, bits_b)
    return 100.0 * flips / len(bits_a)


def run_hash_evaluation():
    record = sample_ehr_record()
    payload = canonical_json(record).encode("utf-8")

    print("=" * 78)
    print("HASH ALGORITHM EVALUATION ON SAMPLE EHR RECORD")
    print("=" * 78)
    print(f"Canonical payload ({len(payload)} bytes):")
    print(payload.decode("utf-8"))
    print("-" * 78)

    results = []
    header = f"{'Algorithm':<12}{'Digest (hex, truncated)':<44}{'Bits':<6}{'Time(us/op)':<14}{'Avalanche %':<12}"
    print(header)
    print("-" * len(header))

    for name in ALGORITHMS:
        digest = digest_of(name, payload)
        bits = len(digest) * 4
        t = time_algorithm(name, payload)
        aval = avalanche_effect(name, payload)
        results.append({
            "algorithm": name,
            "digest": digest,
            "bits": bits,
            "time_us": round(t, 3),
            "avalanche_pct": round(aval, 2),
        })
        trunc = digest[:32] + "..."
        print(f"{name:<12}{trunc:<44}{bits:<6}{t:<14.3f}{aval:<12.2f}")

    print("=" * 78)
    return results


if __name__ == "__main__":
    run_hash_evaluation()
