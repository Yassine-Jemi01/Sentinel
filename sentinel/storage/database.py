"""Local SQLite history with safe schema migrations."""
from __future__ import annotations

import hashlib
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path

from sentinel.core.models import Event, Finding


def data_dir() -> Path:
    base = Path(
        os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share")
    ) / "sentinel"
    base.mkdir(parents=True, exist_ok=True)
    return base


def database_path() -> Path:
    return data_dir() / "events.sqlite3"



def check_integrity() -> str:
    """Check database integrity without creating or modifying the database.

    Returns:
        "ok": Database passed SQLite quick_check.
        "missing": Database file does not exist.
        "corrupt": SQLite reports malformed or invalid database content.
    """
    path = database_path()

    if not path.is_file():
        return "missing"

    uri = path.resolve().as_uri() + "?mode=ro"
    db = sqlite3.connect(uri, uri=True, timeout=10)

    try:
        result = db.execute("PRAGMA quick_check").fetchall()
        if len(result) == 1 and result[0][0] == "ok":
            return "ok"
        return "corrupt"
    except sqlite3.DatabaseError as exc:
        message = str(exc).casefold()
        if "malformed" in message or "not a database" in message:
            return "corrupt"
        raise
    finally:
        db.close()


def _ensure_column(
    db: sqlite3.Connection,
    table: str,
    column: str,
    definition: str,
) -> None:
    """Add a missing column without deleting existing records."""
    existing = {
        row["name"]
        for row in db.execute(f"PRAGMA table_info({table})").fetchall()
    }

    if column not in existing:
        db.execute(
            f"ALTER TABLE {table} ADD COLUMN {column} {definition}"
        )


def connect() -> sqlite3.Connection:
    db = sqlite3.connect(database_path(), timeout=10)
    db.row_factory = sqlite3.Row

    try:
        db.execute("PRAGMA journal_mode=WAL")

        db.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY,
                fingerprint TEXT NOT NULL UNIQUE,
                timestamp TEXT NOT NULL,
                priority INTEGER NOT NULL,
                message TEXT NOT NULL,
                unit TEXT NOT NULL,
                identifier TEXT NOT NULL DEFAULT '',
                source TEXT NOT NULL,
                hostname TEXT NOT NULL DEFAULT ''
            )
        """)

        # Migrate databases created by earlier Sentinel versions.
        _ensure_column(
            db, "events", "identifier",
            "TEXT NOT NULL DEFAULT ''"
        )
        _ensure_column(
            db, "events", "hostname",
            "TEXT NOT NULL DEFAULT ''"
        )

        db.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY,
                fingerprint TEXT NOT NULL UNIQUE,
                title TEXT NOT NULL,
                category TEXT NOT NULL,
                severity TEXT NOT NULL,
                summary TEXT NOT NULL,
                why_it_matters TEXT NOT NULL,
                recommendation TEXT NOT NULL,
                rule_id TEXT NOT NULL
            )
        """)

        db.commit()
        return db

    except Exception:
        db.close()
        raise



@contextmanager
def managed_connection():
    """Manage a SQLite transaction and always close its connection."""
    db = connect()
    try:
        with db:
            yield db
    finally:
        db.close()


def fingerprint(event: Event) -> str:
    raw = "\0".join((
        event.timestamp,
        str(event.priority),
        event.message,
        event.unit,
        event.identifier,
        event.source,
    ))
    return hashlib.sha256(
        raw.encode("utf-8", errors="replace")
    ).hexdigest()


def save_events(events: list[Event]) -> int:
    inserted = 0

    with managed_connection() as db:
        for event in events:
            cursor = db.execute(
                """
                INSERT OR IGNORE INTO events
                (fingerprint, timestamp, priority, message, unit,
                 identifier, source, hostname)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    fingerprint(event),
                    event.timestamp,
                    event.priority,
                    event.message,
                    event.unit,
                    event.identifier,
                    event.source,
                    event.hostname,
                ),
            )
            inserted += max(cursor.rowcount, 0)

    return inserted


def save_findings(findings: list[Finding]) -> int:
    inserted = 0

    with managed_connection() as db:
        for finding in findings:
            key = hashlib.sha256(
                (
                    fingerprint(finding.event) + finding.rule_id
                ).encode()
            ).hexdigest()

            cursor = db.execute(
                """
                INSERT OR IGNORE INTO findings
                (fingerprint, title, category, severity, summary,
                 why_it_matters, recommendation, rule_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    key,
                    finding.title,
                    finding.category,
                    finding.severity,
                    finding.summary,
                    finding.why_it_matters,
                    finding.recommendation,
                    finding.rule_id,
                ),
            )
            inserted += max(cursor.rowcount, 0)

    return inserted


def recent_history(limit: int = 100) -> list[dict]:
    with managed_connection() as db:
        rows = db.execute(
            "SELECT * FROM events ORDER BY id DESC LIMIT ?",
            (max(1, min(limit, 5000)),),
        ).fetchall()

    return [dict(row) for row in rows]
