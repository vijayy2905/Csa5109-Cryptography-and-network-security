"""
ehr_data.py
Sample Electronic Health Record (EHR) and Digital Prescription objects used
throughout the Assignment 5 demonstration.

The records are deliberately structured as canonical JSON strings so that
hashing is byte-deterministic (whitespace / key-order are fixed).
"""

import json
from datetime import datetime


def canonical_json(record: dict) -> str:
    """Serialize a dict to a canonical (sorted-key, fixed-separator) JSON
    string. This is the exact byte-string that gets hashed / signed, so any
    change to any field -- however small -- changes every downstream hash."""
    return json.dumps(record, sort_keys=True, separators=(",", ":"))


def sample_ehr_record() -> dict:
    """A representative Electronic Health Record exchanged between a
    hospital's EHR system and a diagnostic laboratory / insurance portal."""
    return {
        "record_id": "EHR-2026-0917-CHN",
        "record_type": "Diagnosis Report",
        "originating_facility": "Chennai Metropolitan General Hospital",
        "attending_physician": "Dr. S. Ramanathan (Reg. No. TNMC-88291)",
        "patient_id": "PID-77123",
        "patient_name": "Patient A. Kumar",
        "date_of_visit": "2026-08-30",
        "diagnosis": "Type II Diabetes Mellitus, well controlled; mild hypertension",
        "vitals": {
            "bp_mmHg": "128/82",
            "hba1c_percent": 6.4,
            "weight_kg": 74.5
        },
        "clinical_notes": (
            "Patient reports good adherence to prescribed regimen. "
            "Advised continued dietary control and follow-up in 90 days."
        ),
        "timestamp_utc": "2026-08-31T05:42:11Z"
    }


def sample_prescription_record() -> dict:
    """A digital prescription accompanying the EHR, routed to a pharmacy /
    insurance portal for reimbursement processing."""
    return {
        "prescription_id": "RX-2026-0917-CHN",
        "linked_record_id": "EHR-2026-0917-CHN",
        "prescribing_physician": "Dr. S. Ramanathan (Reg. No. TNMC-88291)",
        "patient_id": "PID-77123",
        "medications": [
            {"drug": "Metformin", "dose": "500mg", "frequency": "BID", "duration_days": 90},
            {"drug": "Amlodipine", "dose": "5mg", "frequency": "OD", "duration_days": 90}
        ],
        "pharmacy_instructions": "Dispense generic equivalents permitted.",
        "timestamp_utc": "2026-08-31T05:44:02Z"
    }


def tampered_copy(record: dict) -> dict:
    """Return a maliciously altered copy of an EHR record: an attacker in
    transit changes the diagnosis text (e.g. to commit insurance fraud or
    conceal a condition). Everything else is left byte-identical so the
    demo isolates the effect of a single-field change."""
    forged = json.loads(json.dumps(record))  # deep copy
    if "diagnosis" in forged:
        forged["diagnosis"] = "Type II Diabetes Mellitus, UNCONTROLLED; severe hypertension"
    elif "medications" in forged:
        forged["medications"][0]["dose"] = "1000mg"
    return forged
