"""SHA-256 integrity fingerprinting for digital records.

Every record produces a canonical cryptographic payload built from its
metadata plus the raw evidence-image bytes. The resulting SHA-256 digest is
stored as the record's original fingerprint. Verification simply rebuilds the
canonical payload from the current record and compares digests, which makes
any later modification detectable (tamper-evident storage).
"""

from __future__ import annotations

import hashlib
import json

HASH_VERSION = b"NCB-SHA256-V1\x1e"


def _digest(payload: dict, image_bytes: bytes) -> str:
    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    hasher = hashlib.sha256()
    hasher.update(HASH_VERSION)
    hasher.update(canonical.encode("utf-8"))
    hasher.update(b"\x1e")
    hasher.update(image_bytes)
    return hasher.hexdigest()


def _coord(value: float) -> str:
    return f"{float(value):.6f}"


def generate_hash(
    test_id: str,
    timestamp: str,
    classification: str,
    source: str,
    area: str,
    district: str,
    latitude: float,
    longitude: float,
    image_bytes: bytes,
    officer_id: str,
    notes: str,
) -> str:
    payload = {
        "test_id": str(test_id),
        "timestamp": str(timestamp),
        "classification": str(classification),
        "source": str(source),
        "operational_area": str(area),
        "district": str(district),
        "latitude": _coord(latitude),
        "longitude": _coord(longitude),
        "officer_id": str(officer_id),
        "notes": str(notes),
    }
    return _digest(payload, image_bytes)


def compute_hash_from_record(record: dict, image_bytes: bytes) -> str:
    return generate_hash(
        record["test_id"],
        record["timestamp"],
        record["classification"],
        record["source"],
        record["area"],
        record["district"],
        record["latitude"],
        record["longitude"],
        image_bytes,
        record["officer_id"],
        record["notes"],
    )


def verify_record(record: dict, image_bytes: bytes) -> tuple[bool, str, str]:
    """Return (is_intact, current_hash, reference_hash).

    Sealed records are compared against the CERTIFIED / LOCKED SHA-256 hash
    captured at certification time; pending records are compared against the
    original stored hash. Both references are immutable, so any later change
    to the record fields or the evidence yields a mismatch.
    """
    current = compute_hash_from_record(record, image_bytes)
    stored = record.get("certified_hash") or record.get("stored_hash", "")
    return current == stored, current, stored