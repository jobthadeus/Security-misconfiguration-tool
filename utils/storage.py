"""
Persist scan results to SQLite for historical comparison.

Each scan is stored as a JSON blob so the schema stays flexible as new
checks are added.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from utils.models import ScanResult

DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "data" / "scans.db"


def _ensure_db(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hostname TEXT NOT NULL,
                scanned_at TEXT NOT NULL,
                score INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                report_json TEXT NOT NULL
            )
            """
        )


def save_scan(result: ScanResult, db_path: Path | None = None) -> int:
    """Save a scan result and return the new row id."""
    path = db_path or DEFAULT_DB_PATH
    _ensure_db(path)

    payload = json.dumps(result.to_dict())

    with sqlite3.connect(path) as conn:
        cursor = conn.execute(
            """
            INSERT INTO scans (hostname, scanned_at, score, risk_level, report_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                result.hostname,
                result.scanned_at,
                result.score,
                result.risk_level,
                payload,
            ),
        )
        return cursor.lastrowid or 0


def load_recent_scans(limit: int = 10, db_path: Path | None = None) -> list[dict[str, Any]]:
    """Load the most recent scan summaries from the database."""
    path = db_path or DEFAULT_DB_PATH
    if not path.exists():
        return []

    with sqlite3.connect(path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT id, hostname, scanned_at, score, risk_level
            FROM scans
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    return [dict(row) for row in rows]
