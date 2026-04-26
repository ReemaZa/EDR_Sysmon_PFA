# src/detection/notes.py

import sqlite3
import threading
import json
import os
from datetime import datetime

DB_PATH = os.environ.get("NOTES_DB_PATH", "data/process_notes.db")


class NotesStore:
    """
    Lightweight SQLite store for LLM notes between cycles.

    Schema:
        guid            — ProcessInstance guid (primary key)
        note            — free text, LLM writes whatever it wants
        score_at_note   — score when LLM last looked
        last_llm_at     — timestamp when LLM last looked (ISO string)
        created_at      — when the note was first created
    """

    _instance = None
    _lock      = threading.Lock()

    @classmethod
    def instance(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
        return cls._instance

    def __init__(self):
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        self._conn_lock = threading.Lock()
        self._conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._setup()

    def _setup(self):
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS process_notes (
                guid          TEXT PRIMARY KEY,
                note          TEXT,
                score_at_note INTEGER,
                last_llm_at   TEXT,
                created_at    TEXT
            )
        """)
        self._conn.commit()

    # ── public API ────────────────────────────────────────────────

    def get(self, guid: str) -> dict | None:
        with self._conn_lock:
            row = self._conn.execute(
                "SELECT * FROM process_notes WHERE guid = ?", (guid,)
            ).fetchone()
        return dict(row) if row else None

    def upsert(self, guid: str, note: str, score: int):
        now = datetime.utcnow().isoformat()
        with self._conn_lock:
            self._conn.execute("""
                INSERT INTO process_notes (guid, note, score_at_note, last_llm_at, created_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(guid) DO UPDATE SET
                    note          = excluded.note,
                    score_at_note = excluded.score_at_note,
                    last_llm_at   = excluded.last_llm_at
            """, (guid, note, score, now, now))
            self._conn.commit()

    def delete(self, guid: str):
        with self._conn_lock:
            self._conn.execute(
                "DELETE FROM process_notes WHERE guid = ?", (guid,)
            )
            self._conn.commit()

    def delete_many(self, guids: list):
        if not guids:
            return
        placeholders = ",".join("?" * len(guids))
        with self._conn_lock:
            self._conn.execute(
                f"DELETE FROM process_notes WHERE guid IN ({placeholders})", guids
            )
            self._conn.commit()

    def get_all_guids(self) -> list:
        with self._conn_lock:
            rows = self._conn.execute(
                "SELECT guid FROM process_notes"
            ).fetchall()
        return [r["guid"] for r in rows]

    def get_stale(self, older_than_hours: int) -> list:
        """Notes not updated in N hours."""
        from datetime import timedelta
        cutoff = (datetime.utcnow() - timedelta(hours=older_than_hours)).isoformat()
        with self._conn_lock:
            rows = self._conn.execute(
                "SELECT * FROM process_notes WHERE last_llm_at < ?", (cutoff,)
            ).fetchall()
        return [dict(r) for r in rows]