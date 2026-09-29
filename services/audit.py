"""Persistent audit log for the NCB Digital Chain of Custody node.

Every significant record action is appended to a persistent table in the
secure vault, so audit history survives page refreshes and application
restarts.
"""

from __future__ import annotations

from datetime import datetime

from services import database

ACTIONS = (
    "RECORD CREATED",
    "RECORD MODIFIED",
    "INTEGRITY VERIFIED",
    "INTEGRITY MISMATCH",
    "MAGISTRATE_CERTIFIED",
)


def _now_text() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def log_action(test_id: str, action: str, actor: str, detail: str = "") -> None:
    with database.get_connection() as conn:
        conn.execute(
            "INSERT INTO audit_log (test_id, action, actor, timestamp, detail) "
            "VALUES (?, ?, ?, ?, ?)",
            (test_id, action, actor, _now_text(), detail),
        )


def fetch_audit(
    limit: int | None = None,
    test_id: str | None = None,
    action: str | None = None,
) -> list[dict]:
    clauses: list[str] = []
    params: list = []

    if test_id:
        clauses.append("test_id LIKE ?")
        params.append(f"%{test_id}%")
    if action:
        clauses.append("action = ?")
        params.append(action)

    where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
    sql = (
        f"SELECT test_id, action, actor, timestamp, detail FROM audit_log{where} "
        "ORDER BY timestamp DESC, id DESC"
    )
    if limit is not None:
        sql += " LIMIT ?"
        params.append(limit)

    with database.get_connection() as conn:
        rows = conn.execute(sql, params).fetchall()
    return [dict(r) for r in rows]