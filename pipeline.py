"""
pipeline.py
End-to-end medical document integrity and authentication pipeline combining
SHA-256 hashing with RSA-2048/PSS digital signatures, applied to BOTH the
EHR diagnosis record and the linked digital prescription.

Simulates the real transmission scenario described in the problem statement:
    Hospital (signer)  --->  Diagnostic Lab / Insurance Portal (verifier)

Three end-to-end scenarios are demonstrated:
    1. Genuine, unaltered transmission            -> ACCEPT
    2. Transmission tampered with in transit       -> REJECT (integrity)
    3. Transmission with signature stripped/absent -> REJECT (authentication)
"""

import hashlib
import json
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

from ehr_data import canonical_json, sample_ehr_record, sample_prescription_record, tampered_copy


def sha256_hash(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sign_document(private_key, payload: bytes) -> bytes:
    return private_key.sign(
        payload,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )


def verify_document(public_key, payload: bytes, signature: bytes) -> bool:
    try:
        public_key.verify(
            signature,
            payload,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False


class HospitalSigningAuthority:
    """Represents the originating healthcare facility's signing identity."""

    def __init__(self, facility_name: str):
        self.facility_name = facility_name
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()

    def package_document(self, record: dict) -> dict:
        """Hash + sign a record, producing a transmissible envelope containing
        the original document, its hash, and its digital signature."""
        payload = canonical_json(record).encode("utf-8")
        digest = sha256_hash(payload)
        signature = sign_document(self.private_key, payload)
        return {
            "document": record,
            "sha256_digest": digest,
            "signature_hex": signature.hex(),
            "signer": self.facility_name,
        }


class VerifierPortal:
    """Represents the receiving diagnostic lab / insurance portal."""

    def __init__(self, name: str):
        self.name = name

    def verify_envelope(self, envelope: dict, signer_public_key) -> dict:
        payload = canonical_json(envelope["document"]).encode("utf-8")
        recomputed_digest = sha256_hash(payload)
        digest_match = recomputed_digest == envelope["sha256_digest"]

        signature = bytes.fromhex(envelope["signature_hex"])
        sig_valid = verify_document(signer_public_key, payload, signature)

        outcome = "ACCEPTED" if (digest_match and sig_valid) else "REJECTED"
        return {
            "verifier": self.name,
            "digest_match": digest_match,
            "signature_valid": sig_valid,
            "outcome": outcome,
        }


def run_pipeline_demo():
    print("=" * 78)
    print("END-TO-END EHR INTEGRITY & AUTHENTICATION PIPELINE (SHA-256 + RSA-PSS)")
    print("=" * 78)

    hospital = HospitalSigningAuthority("Chennai Metropolitan General Hospital")
    lab = VerifierPortal("MedCore Diagnostic Laboratory")
    insurer = VerifierPortal("SecureHealth Insurance Portal")

    ehr = sample_ehr_record()
    rx = sample_prescription_record()

    results = []

    # ---- Scenario 1: genuine transmission ----
    print("\n--- Scenario 1: Genuine EHR transmitted to Diagnostic Lab ---")
    envelope = hospital.package_document(ehr)
    outcome = lab.verify_envelope(envelope, hospital.public_key)
    print(f"SHA-256 digest   : {envelope['sha256_digest']}")
    print(f"Signature (trunc): {envelope['signature_hex'][:48]}...")
    print(f"Verifier result  : {outcome}")
    results.append(("Genuine EHR -> Lab", outcome))

    # ---- Scenario 2: tampered in transit ----
    print("\n--- Scenario 2: EHR tampered in transit (diagnosis altered) ---")
    forged_ehr = tampered_copy(ehr)
    # Attacker forwards the ORIGINAL signature/digest alongside the ALTERED document
    tampered_envelope = {
        "document": forged_ehr,
        "sha256_digest": envelope["sha256_digest"],
        "signature_hex": envelope["signature_hex"],
        "signer": envelope["signer"],
    }
    outcome2 = lab.verify_envelope(tampered_envelope, hospital.public_key)
    print(f"Original diagnosis : {ehr['diagnosis']}")
    print(f"Altered diagnosis  : {forged_ehr['diagnosis']}")
    print(f"Recomputed digest matches stored digest? {outcome2['digest_match']}")
    print(f"Signature still valid over altered text?  {outcome2['signature_valid']}")
    print(f"Verifier result    : {outcome2}")
    results.append(("Tampered EHR -> Lab", outcome2))

    # ---- Scenario 3: prescription signed & routed to insurer, then stripped signature ----
    print("\n--- Scenario 3: Prescription with signature stripped en route to Insurer ---")
    rx_envelope = hospital.package_document(rx)
    stripped_envelope = dict(rx_envelope)
    stripped_envelope["signature_hex"] = "00" * len(bytes.fromhex(rx_envelope["signature_hex"]))
    outcome3 = insurer.verify_envelope(stripped_envelope, hospital.public_key)
    print(f"Prescription digest: {rx_envelope['sha256_digest']}")
    print(f"Verifier result    : {outcome3}")
    results.append(("Unsigned/stripped Rx -> Insurer", outcome3))

    print("\n" + "=" * 78)
    print("SUMMARY")
    print("=" * 78)
    for label, o in results:
        print(f"  {label:<38} -> {o['outcome']}")
    print("=" * 78)

    return results


if __name__ == "__main__":
    run_pipeline_demo()
