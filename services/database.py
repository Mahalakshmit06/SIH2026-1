"""Secure storage layer for the NCB Digital Chain of Custody node.

This module isolates every database interaction behind simple functions so the
underlying SQLite vault can later be replaced by a hardened production database
(e.g. SQLCipher behind a mutual-TLS service bridge) without touching the UI.

All queries that feed the dashboard, record explorer, area analysis and
audit views live here.
"""

from __future__ import annotations

import os
import sqlite3
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("NCB_DATA_DIR", PROJECT_ROOT / "data"))
EVIDENCE_DIR = DATA_DIR / "evidence"
DB_PATH = DATA_DIR / "ncb_vault.db"

CLASSIFICATIONS = ("POSITIVE", "NEGATIVE", "INCONCLUSIVE")

CERT_STATUS_PENDING = "PENDING"
CERT_STATUS_SEALED = "LEGALLY SEALED (SEC 52A)"
CERTIFICATION_STATUSES = (CERT_STATUS_PENDING, CERT_STATUS_SEALED)

_SCHEMA_RECORDS = """
CREATE TABLE IF NOT EXISTS records (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    test_id       TEXT    NOT NULL UNIQUE,
    timestamp     TEXT    NOT NULL,
    classification TEXT   NOT NULL,
    source        TEXT    NOT NULL,
    area          TEXT    NOT NULL,
    district      TEXT    NOT NULL,
    latitude      REAL    NOT NULL,
    longitude     REAL    NOT NULL,
    image_name    TEXT    NOT NULL,
    officer_id    TEXT    NOT NULL,
    notes         TEXT    NOT NULL DEFAULT '',
    stored_hash   TEXT    NOT NULL,
    created_at    TEXT    NOT NULL,
    certification_status  TEXT NOT NULL DEFAULT 'PENDING',
    certification_timestamp TEXT,
    certifying_magistrate_id TEXT,
    certified_hash TEXT
)
"""

_SCHEMA_AUDIT = """
CREATE TABLE IF NOT EXISTS audit_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    test_id   TEXT NOT NULL,
    action    TEXT NOT NULL,
    actor     TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    detail    TEXT NOT NULL DEFAULT ''
)
"""


def _ensure_dirs() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)


def get_connection() -> sqlite3.Connection:
    _ensure_dirs()
    conn = sqlite3.connect(str(DB_PATH), timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def _ensure_columns(conn: sqlite3.Connection) -> None:
    existing = {r["name"] for r in conn.execute("PRAGMA table_info(records)").fetchall()}
    additions = {
        "certification_status": "TEXT NOT NULL DEFAULT 'PENDING'",
        "certification_timestamp": "TEXT",
        "certifying_magistrate_id": "TEXT",
        "certified_hash": "TEXT",
    }
    for name, decl in additions.items():
        if name not in existing:
            conn.execute(f"ALTER TABLE records ADD COLUMN {name} {decl}")


def init_db() -> None:
    _ensure_dirs()
    with get_connection() as conn:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute(_SCHEMA_RECORDS)
        conn.execute(_SCHEMA_AUDIT)
        _ensure_columns(conn)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_records_test_id ON records(test_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_records_area ON records(area)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_records_district ON records(district)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_records_cert_status ON records(certification_status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_test_id ON audit_log(test_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action)")


def clear_all() -> None:
    """Remove every record and audit entry, leaving an empty schema."""
    init_db()
    with get_connection() as conn:
        conn.execute("DELETE FROM records")
        conn.execute("DELETE FROM audit_log")


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------

def insert_record(rec: dict) -> None:
    sql = """
        INSERT INTO records
            (test_id, timestamp, classification, source, area, district,
             latitude, longitude, image_name, officer_id, notes, stored_hash,
             created_at)
        VALUES
            (:test_id, :timestamp, :classification, :source, :area, :district,
             :latitude, :longitude, :image_name, :officer_id, :notes,
             :stored_hash, :created_at)
    """
    with get_connection() as conn:
        conn.execute(sql, rec)


def get_record(test_id: str) -> dict | None:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM records WHERE test_id = ?", (test_id,)
        ).fetchone()
    return dict(row) if row else None


def _build_filter(filters: dict | None) -> tuple[str, list]:
    clauses: list[str] = []
    params: list = []
    filters = filters or {}

    test_id = filters.get("test_id")
    if test_id:
        clauses.append("test_id LIKE ?")
        params.append(f"%{test_id}%")

    officer_id = filters.get("officer_id")
    if officer_id:
        clauses.append("officer_id LIKE ?")
        params.append(f"%{officer_id}%")

    source = filters.get("source")
    if source:
        clauses.append("source LIKE ?")
        params.append(f"%{source}%")

    classifications = filters.get("classifications")
    if classifications:
        cls_list = list(classifications)
        if cls_list:
            placeholders = ",".join("?" * len(cls_list))
            clauses.append(f"classification IN ({placeholders})")
            params.extend(cls_list)

    district = filters.get("district")
    if district:
        clauses.append("district = ?")
        params.append(district)

    area = filters.get("area")
    if area:
        clauses.append("area = ?")
        params.append(area)

    certification_status = filters.get("certification_status")
    if certification_status:
        clauses.append("certification_status = ?")
        params.append(certification_status)

    where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
    return where, params


def list_records(filters: dict | None = None, limit: int | None = None) -> list[dict]:
    where, params = _build_filter(filters)
    sql = f"SELECT * FROM records{where} ORDER BY timestamp DESC, test_id DESC"
    if limit is not None:
        sql += " LIMIT ?"
        params.append(limit)
    with get_connection() as conn:
        rows = conn.execute(sql, params).fetchall()
    return [dict(r) for r in rows]


_UPDATABLE_FIELDS = {"classification", "area", "notes"}


def update_record_fields(test_id: str, fields: dict) -> None:
    allowed = {k: v for k, v in fields.items() if k in _UPDATABLE_FIELDS}
    if not allowed:
        return
    with get_connection() as conn:
        row = conn.execute(
            "SELECT certification_status FROM records WHERE test_id = ?", (test_id,)
        ).fetchone()
        if row and row["certification_status"] == CERT_STATUS_SEALED:
            return
        set_clause = ", ".join(f"{k} = ?" for k in allowed)
        params = list(allowed.values()) + [test_id]
        conn.execute(f"UPDATE records SET {set_clause} WHERE test_id = ?", params)


def certify_record(
    test_id: str,
    magistrate_id: str,
    certification_ts: str | None = None,
    certified_hash: str | None = None,
) -> dict | None:
    """Lock a record under Section 52A legal certification.

    Certification succeeds only for a verified record. The exact SHA-256 hash
    that was verified (``certified_hash``) is stored separately in the records
    table as the CERTIFIED / LOCKED SHA-256 hash. The lock is permanent: once
    sealed, the record becomes read-only and the certified hash is the only
    reference integrity verification is compared against. If no hash is
    supplied the original stored hash is locked, preserving the previously
    verified fingerprint.
    """
    ts = certification_ts or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with get_connection() as conn:
        if certified_hash is None:
            row = conn.execute(
                "SELECT stored_hash FROM records WHERE test_id = ?", (test_id,)
            ).fetchone()
            if row is None:
                return None
            certified_hash = row["stored_hash"]
        conn.execute(
            "UPDATE records SET certification_status = ?, certification_timestamp = ?, "
            "certifying_magistrate_id = ?, certified_hash = ? WHERE test_id = ?",
            (CERT_STATUS_SEALED, ts, magistrate_id, certified_hash, test_id),
        )
    return get_record(test_id)


def record_counts() -> dict:
    with get_connection() as conn:
        total = conn.execute("SELECT COUNT(*) AS c FROM records").fetchone()["c"]
        counts = {"total": total}
        for classification in CLASSIFICATIONS:
            row = conn.execute(
                "SELECT COUNT(*) AS c FROM records WHERE classification = ?",
                (classification,),
            ).fetchone()
            counts[classification.lower()] = row["c"]
    return counts


def distinct_values(column: str) -> list[str]:
    with get_connection() as conn:
        rows = conn.execute(
            f"SELECT DISTINCT {column} AS v FROM records "
            f"WHERE {column} IS NOT NULL AND {column} <> '' ORDER BY {column}",
        ).fetchall()
    return [r["v"] for r in rows]


def next_test_id(now: datetime | None = None) -> str:
    now = now or datetime.now()
    prefix = f"NCB-{now:%Y%m%d}-"
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT test_id FROM records WHERE test_id LIKE ?", (prefix + "%",)
        ).fetchall()
    seq = 0
    for r in rows:
        try:
            seq = max(seq, int(r["test_id"][len(prefix):]))
        except ValueError:
            continue
    return f"{prefix}{seq + 1:03d}"


# ---------------------------------------------------------------------------
# Evidence vault
# ---------------------------------------------------------------------------

def save_evidence(data: bytes, image_name: str) -> Path:
    _ensure_dirs()
    path = EVIDENCE_DIR / image_name
    path.write_bytes(data)
    return path


def evidence_path(image_name: str) -> Path:
    return EVIDENCE_DIR / image_name


def read_evidence_bytes(image_name: str) -> bytes:
    return (EVIDENCE_DIR / image_name).read_bytes()


def evidence_exists(image_name: str) -> bool:
    return (EVIDENCE_DIR / image_name).exists()