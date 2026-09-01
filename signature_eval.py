"""
signature_eval.py
Implements and evaluates two digital signature schemes for EHR / prescription
authentication and non-repudiation:

  1. RSA-2048 with PSS padding and SHA-256   (RSASSA-PSS, PKCS#1 v2.2)
  2. ECDSA on the NIST P-256 curve with SHA-256

Workflow per scheme:
  a. Key generation (Health IT Security Analyst / originating facility keeps
     the private key; the private key never leaves the issuing hospital's HSM
     in a real deployment)
  b. hash(record) -> sign(hash) with private key   -> signature bytes
  c. Recipient (lab / insurer) uses the ORIGINATOR'S PUBLIC KEY ONLY to
     verify -- demonstrating non-repudiation (only the holder of the private
     key could have produced a valid signature) and authentication (identity
     of the origin is cryptographically bound to the document).
  d. Tamper test: verification is attempted against a maliciously altered
     copy of the record to show integrity enforcement.
"""

import time
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding, utils
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

from ehr_data import canonical_json, sample_ehr_record, tampered_copy

N_ITER = 200  # signature ops are expensive relative to hashing


# ---------------------------------------------------------------- RSA-PSS --
def rsa_generate_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()


def rsa_sign(private_key, message: bytes) -> bytes:
    return private_key.sign(
        message,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )


def rsa_verify(public_key, message: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False


# ------------------------------------------------------------------ ECDSA --
def ec_generate_keypair():
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key, private_key.public_key()


def ec_sign(private_key, message: bytes) -> bytes:
    return private_key.sign(message, ec.ECDSA(hashes.SHA256()))


def ec_verify(public_key, message: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


# --------------------------------------------------------------- Timing ---
def time_fn(fn, *args, n=N_ITER):
    start = time.perf_counter()
    for _ in range(n):
        fn(*args)
    return ((time.perf_counter() - start) / n) * 1e3  # ms/op


def run_signature_evaluation():
    record = sample_ehr_record()
    payload = canonical_json(record).encode("utf-8")
    forged_payload = canonical_json(tampered_copy(record)).encode("utf-8")

    print("=" * 78)
    print("DIGITAL SIGNATURE EVALUATION -- EHR ORIGIN AUTHENTICATION")
    print("=" * 78)

    results = {}

    # ---- RSA-PSS-2048 ----
    print("\n[1] RSA-2048 / PSS / SHA-256")
    rsa_priv, rsa_pub = rsa_generate_keypair()
    sig_rsa = rsa_sign(rsa_priv, payload)
    valid_genuine = rsa_verify(rsa_pub, payload, sig_rsa)
    valid_forged = rsa_verify(rsa_pub, forged_payload, sig_rsa)

    t_keygen = time_fn(lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048), n=5)
    t_sign = time_fn(lambda: rsa_sign(rsa_priv, payload))
    t_verify = time_fn(lambda: rsa_verify(rsa_pub, payload, sig_rsa))
    sig_len = len(sig_rsa)

    print(f"  Signature (hex, truncated): {sig_rsa.hex()[:64]}...")
    print(f"  Signature length: {sig_len} bytes ({sig_len*8} bits)")
    print(f"  Verify(genuine record, original signature)  -> {valid_genuine}")
    print(f"  Verify(TAMPERED record, original signature) -> {valid_forged}  (expected: False)")
    print(f"  Key generation time : {t_keygen:.3f} ms (avg of 5)")
    print(f"  Sign time           : {t_sign:.4f} ms/op")
    print(f"  Verify time         : {t_verify:.4f} ms/op")

    results["RSA-2048-PSS-SHA256"] = {
        "sig_len_bytes": sig_len,
        "valid_genuine": valid_genuine,
        "valid_forged": valid_forged,
        "keygen_ms": round(t_keygen, 3),
        "sign_ms": round(t_sign, 4),
        "verify_ms": round(t_verify, 4),
    }

    # ---- ECDSA P-256 ----
    print("\n[2] ECDSA / NIST P-256 / SHA-256")
    ec_priv, ec_pub = ec_generate_keypair()
    sig_ec = ec_sign(ec_priv, payload)
    valid_genuine_ec = ec_verify(ec_pub, payload, sig_ec)
    valid_forged_ec = ec_verify(ec_pub, forged_payload, sig_ec)

    t_keygen_ec = time_fn(lambda: ec.generate_private_key(ec.SECP256R1()), n=50)
    t_sign_ec = time_fn(lambda: ec_sign(ec_priv, payload))
    t_verify_ec = time_fn(lambda: ec_verify(ec_pub, payload, sig_ec))
    sig_len_ec = len(sig_ec)

    print(f"  Signature (hex, truncated): {sig_ec.hex()[:64]}...")
    print(f"  Signature length: {sig_len_ec} bytes ({sig_len_ec*8} bits, DER-encoded)")
    print(f"  Verify(genuine record, original signature)  -> {valid_genuine_ec}")
    print(f"  Verify(TAMPERED record, original signature) -> {valid_forged_ec}  (expected: False)")
    print(f"  Key generation time : {t_keygen_ec:.3f} ms (avg of 50)")
    print(f"  Sign time           : {t_sign_ec:.4f} ms/op")
    print(f"  Verify time         : {t_verify_ec:.4f} ms/op")

    results["ECDSA-P256-SHA256"] = {
        "sig_len_bytes": sig_len_ec,
        "valid_genuine": valid_genuine_ec,
        "valid_forged": valid_forged_ec,
        "keygen_ms": round(t_keygen_ec, 3),
        "sign_ms": round(t_sign_ec, 4),
        "verify_ms": round(t_verify_ec, 4),
    }

    # ---- Non-repudiation demo: wrong key cannot forge a valid signature ----
    print("\n[3] Non-repudiation check: attacker without the private key")
    attacker_priv, attacker_pub = rsa_generate_keypair()
    forged_sig_attempt = rsa_sign(attacker_priv, payload)
    accepted_under_hospital_pubkey = rsa_verify(rsa_pub, payload, forged_sig_attempt)
    print(f"  Attacker signs the (unaltered) record with THEIR OWN key.")
    print(f"  Verifying that signature against the HOSPITAL's public key -> "
          f"{accepted_under_hospital_pubkey}  (expected: False)")
    results["non_repudiation_forged_key_rejected"] = not accepted_under_hospital_pubkey

    print("=" * 78)
    return results


if __name__ == "__main__":
    run_signature_evaluation()
