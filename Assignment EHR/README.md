# SecureEHR - Cryptographic Security Portal

## Evaluation of Cryptographic Hash Functions and Digital Signatures in Electronic Health Record Security

SecureEHR is a web-based demonstration portal for evaluating cryptographic security mechanisms used to protect Electronic Health Records (EHR).

The application demonstrates:

- SHA-256 hashing
- Digital signatures
- RSA-2048/PSS
- ECDSA P-256
- EHR integrity verification
- Tamper detection
- Hash algorithm comparison
- Digital signature performance comparison
- Hospital → Laboratory → Insurance workflow
- Security validation test cases TC-01 to TC-10

---

## Project Architecture

```text
Hospital
    |
    |  EHR Document
    v
Canonical JSON
    |
    v
SHA-256 Digest
    |
    v
Digital Signature
    |
    v
Secure EHR Envelope
    |
    v
Laboratory
    |
    v
Digest Verification
    +
Signature Verification
    |
    v
ACCEPT / REJECT
