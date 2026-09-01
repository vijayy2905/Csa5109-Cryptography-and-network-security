from flask import Flask, render_template, request, jsonify
import hashlib
import json
import time

from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

app = Flask(__name__)

# ============================================================
# EHR CRYPTOGRAPHIC SECURITY PORTAL
# ============================================================

HOSPITAL = "Chennai Metropolitan General Hospital"
LABORATORY = "MedCore Diagnostic Laboratory"
INSURANCE = "SecureHealth Insurance Portal"

# Demo keys.
# Production systems should use HSM/KMS/PKI.
RSA_PRIVATE = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
RSA_PUBLIC = RSA_PRIVATE.public_key()

ECDSA_PRIVATE = ec.generate_private_key(ec.SECP256R1())
ECDSA_PUBLIC = ECDSA_PRIVATE.public_key()


# ============================================================
# EHR DATA
# ============================================================

def sample_ehr():
    return {
        "patient_id": "EHR-2026-001",
        "patient_name": "Demo Patient",
        "age": 34,
        "gender": "Male",
        "diagnosis": "Viral Fever",
        "doctor": "Dr. K. Ramesh Kumar",
        "hospital": HOSPITAL,
        "department": "General Medicine",
        "date": "2026-09-01",
        "prescription": {
            "medicine": "Paracetamol",
            "dosage": "500 mg",
            "frequency": "Twice daily",
            "duration": "5 days"
        }
    }


def sample_prescription():
    return {
        "prescription_id": "RX-2026-001",
        "patient_id": "EHR-2026-001",
        "medicine": "Paracetamol",
        "dosage": "500 mg",
        "frequency": "Twice daily",
        "duration": "5 days",
        "doctor": "Dr. K. Ramesh Kumar",
        "hospital": HOSPITAL,
        "date": "2026-09-01"
    }


# ============================================================
# CANONICAL JSON
# ============================================================

def canonical_json(data):
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":")
    )


def payload_bytes(data):
    return canonical_json(data).encode("utf-8")


# ============================================================
# SHA-256
# ============================================================

def sha256_digest(data):
    return hashlib.sha256(payload_bytes(data)).hexdigest()


# ============================================================
# TAMPERING
# ============================================================

def tampered_record(data):
    modified = json.loads(json.dumps(data))

    if "diagnosis" in modified:
        modified["diagnosis"] = "Modified Diagnosis"

    elif "medicine" in modified:
        modified["dosage"] = "1000 mg"

    elif "prescription" in modified:
        modified["prescription"]["dosage"] = "1000 mg"

    return modified


# ============================================================
# RSA-2048 / PSS
# ============================================================

def rsa_sign(data):

    return RSA_PRIVATE.sign(
        payload_bytes(data),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


def rsa_verify(data, signature):

    try:

        RSA_PUBLIC.verify(
            signature,
            payload_bytes(data),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return True

    except InvalidSignature:
        return False

    except Exception:
        return False


# ============================================================
# ECDSA P-256
# ============================================================

def ecdsa_sign(data):

    return ECDSA_PRIVATE.sign(
        payload_bytes(data),
        ec.ECDSA(hashes.SHA256())
    )


def ecdsa_verify(data, signature):

    try:

        ECDSA_PUBLIC.verify(
            signature,
            payload_bytes(data),
            ec.ECDSA(hashes.SHA256())
        )

        return True

    except InvalidSignature:
        return False

    except Exception:
        return False


# ============================================================
# CREATE SECURE ENVELOPE
# ============================================================

def create_envelope(data, scheme):

    if scheme == "ECDSA P-256":
        signature = ecdsa_sign(data)
    else:
        signature = rsa_sign(data)

    return {
        "document": data,
        "sha256_digest": sha256_digest(data),
        "signature_hex": signature.hex(),
        "signer": HOSPITAL,
        "recipient": LABORATORY,
        "signature_scheme": scheme,
        "hash_algorithm": "SHA-256",
        "timestamp": time.strftime(
            "%Y-%m-%d %H:%M:%S UTC",
            time.gmtime()
        )
    }


# ============================================================
# VERIFY
# ============================================================

def verify_envelope(envelope):

    document = envelope.get("document", {})

    stored_digest = envelope.get(
        "sha256_digest",
        ""
    )

    calculated_digest = sha256_digest(document)

    digest_match = (
        stored_digest == calculated_digest
    )

    try:

        signature = bytes.fromhex(
            envelope.get("signature_hex", "")
        )

    except ValueError:

        signature = b""

    scheme = envelope.get(
        "signature_scheme",
        "RSA-2048/PSS"
    )

    if scheme == "ECDSA P-256":
        signature_valid = ecdsa_verify(
            document,
            signature
        )

    else:
        signature_valid = rsa_verify(
            document,
            signature
        )

    accepted = (
        digest_match and
        signature_valid
    )

    return {
        "digest_match": digest_match,
        "signature_valid": signature_valid,
        "recomputed_digest": calculated_digest,
        "outcome": "ACCEPTED" if accepted else "REJECTED"
    }


# ============================================================
# ROUTES
# ============================================================

@app.route("/")
def home():

    return render_template("index.html")


@app.route("/api/sample")
def get_sample():

    return jsonify({
        "ehr": sample_ehr(),
        "prescription": sample_prescription()
    })


@app.route("/api/sign", methods=["POST"])
def sign_document():

    data = request.get_json(force=True)

    document = data.get(
        "document",
        sample_ehr()
    )

    scheme = data.get(
        "scheme",
        "ECDSA P-256"
    )

    envelope = create_envelope(
        document,
        scheme
    )

    return jsonify(envelope)


@app.route("/api/verify", methods=["POST"])
def verify_document():

    envelope = request.get_json(force=True)

    result = verify_envelope(
        envelope
    )

    return jsonify(result)


@app.route("/api/tamper", methods=["POST"])
def tamper_document():

    data = request.get_json(force=True)

    document = data.get(
        "document",
        sample_ehr()
    )

    modified = tampered_record(
        document
    )

    return jsonify(modified)


# ============================================================
# HASH ANALYSIS
# ============================================================

def hash_functions():

    return {
        "MD5": lambda x: hashlib.md5(x).digest(),
        "SHA-1": lambda x: hashlib.sha1(x).digest(),
        "SHA-256": lambda x: hashlib.sha256(x).digest(),
        "SHA-512": lambda x: hashlib.sha512(x).digest(),
        "SHA3-256": lambda x: hashlib.sha3_256(x).digest(),
        "BLAKE2b-256": lambda x: hashlib.blake2b(
            x,
            digest_size=32
        ).digest()
    }


def avalanche_test(function, data):

    original = function(data)

    modified = bytearray(data)

    if len(modified) > 0:
        modified[0] ^= 1

    changed = function(bytes(modified))

    total_bits = len(original) * 8
    changed_bits = 0

    for a, b in zip(original, changed):

        xor_value = a ^ b

        changed_bits += bin(
            xor_value
        ).count("1")

    return (
        changed_bits /
        total_bits *
        100
    )


@app.route("/api/hash-analysis")
def hash_analysis():

    record = sample_ehr()

    data = payload_bytes(record)

    functions = hash_functions()

    results = []

    for name, function in functions.items():

        start = time.perf_counter()

        for _ in range(1000):
            function(data)

        elapsed = (
            time.perf_counter() -
            start
        )

        microseconds = (
            elapsed /
            1000 *
            1_000_000
        )

        digest = function(data)

        avalanche = avalanche_test(
            function,
            data
        )

        results.append({
            "algorithm": name,
            "bits": len(digest) * 8,
            "time_us": round(
                microseconds,
                3
            ),
            "avalanche_pct": round(
                avalanche,
                2
            )
        })

    return jsonify(results)


# ============================================================
# DIGITAL SIGNATURE ANALYSIS
# ============================================================

@app.route("/api/signature-analysis")
def signature_analysis():

    document = sample_ehr()

    schemes = [
        (
            "RSA-2048 / PSS",
            rsa_sign,
            rsa_verify
        ),
        (
            "ECDSA / P-256",
            ecdsa_sign,
            ecdsa_verify
        )
    ]

    results = []

    for name, signer, verifier in schemes:

        signature = signer(document)

        start = time.perf_counter()

        for _ in range(50):
            signer(document)

        sign_time = (
            time.perf_counter() -
            start
        ) / 50 * 1000

        start = time.perf_counter()

        for _ in range(50):
            verifier(
                document,
                signature
            )

        verify_time = (
            time.perf_counter() -
            start
        ) / 50 * 1000

        modified = tampered_record(
            document
        )

        results.append({
            "scheme": name,
            "signature_bytes": len(signature),
            "sign_ms": round(
                sign_time,
                4
            ),
            "verify_ms": round(
                verify_time,
                4
            ),
            "genuine": verifier(
                document,
                signature
            ),
            "tampered": verifier(
                modified,
                signature
            )
        })

    return jsonify(results)


# ============================================================
# TEST CASES
# ============================================================

@app.route("/api/tests")
def tests():

    document = sample_ehr()

    envelope = create_envelope(
        document,
        "ECDSA P-256"
    )

    modified_document = tampered_record(
        document
    )

    modified_envelope = dict(
        envelope
    )

    modified_envelope[
        "document"
    ] = modified_document

    stripped_envelope = dict(
        envelope
    )

    stripped_envelope[
        "signature_hex"
    ] = ""

    tests = []

    tests.append({
        "id": "TC-01",
        "name": "Hash determinism",
        "pass": (
            sha256_digest(document)
            ==
            sha256_digest(document)
        )
    })

    tests.append({
        "id": "TC-02",
        "name": "Genuine signature verification",
        "pass": (
            verify_envelope(
                envelope
            )["outcome"]
            == "ACCEPTED"
        )
    })

    tests.append({
        "id": "TC-03",
        "name": "Tampered diagnosis rejected",
        "pass": (
            verify_envelope(
                modified_envelope
            )["outcome"]
            == "REJECTED"
        )
    })

    tests.append({
        "id": "TC-04",
        "name": "Signature protects document",
        "pass": (
            not ecdsa_verify(
                modified_document,
                bytes.fromhex(
                    envelope[
                        "signature_hex"
                    ]
                )
            )
        )
    })

    tests.append({
        "id": "TC-05",
        "name": "Stripped signature rejected",
        "pass": (
            verify_envelope(
                stripped_envelope
            )["outcome"]
            == "REJECTED"
        )
    })

    prescription = sample_prescription()

    tests.append({
        "id": "TC-06",
        "name": "Altered prescription changes digest",
        "pass": (
            sha256_digest(
                prescription
            )
            !=
            sha256_digest(
                tampered_record(
                    prescription
                )
            )
        )
    })

    functions = hash_functions()

    avalanche = avalanche_test(
        functions["SHA-256"],
        payload_bytes(document)
    )

    tests.append({
        "id": "TC-07",
        "name": "SHA-256 avalanche behaviour",
        "pass": (
            40 <= avalanche <= 60
        )
    })

    tests.append({
        "id": "TC-08",
        "name": "Hospital to Lab accepted",
        "pass": (
            verify_envelope(
                envelope
            )["outcome"]
            == "ACCEPTED"
        )
    })

    tests.append({
        "id": "TC-09",
        "name": "Tampered Hospital to Lab rejected",
        "pass": (
            verify_envelope(
                modified_envelope
            )["outcome"]
            == "REJECTED"
        )
    })

    tests.append({
        "id": "TC-10",
        "name": "Unsigned document rejected",
        "pass": (
            verify_envelope(
                stripped_envelope
            )["outcome"]
            == "REJECTED"
        )
    })

    return jsonify(tests)


# ============================================================
# START SERVER
# ============================================================

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )
