"""
subject_registry.py

Maintains the mapping:   PII fingerprint  <-->  data_subject_id (UUID)

This is what lets the system say "these 47 chunks across 12 documents all
belong to the same natural person" even though they were ingested at
different times, from different files, possibly with slightly different
formatting of the same email/phone.

Only fingerprints (salted hashes) are stored here -- never the raw PII
value -- so this table is not itself a compliance liability.
"""

from __future__ import annotations

import sqlite3
import uuid
from contextlib import closing
from typing import List, Optional


SCHEMA = """
CREATE TABLE IF NOT EXISTS subjects (
    subject_id TEXT PRIMARY KEY,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    status TEXT DEFAULT 'active'  -- active | erased
);

CREATE TABLE IF NOT EXISTS fingerprints (
    fingerprint TEXT PRIMARY KEY,
    subject_id TEXT NOT NULL,
    entity_type TEXT,
    FOREIGN KEY (subject_id) REFERENCES subjects(subject_id)
);
"""


class SubjectRegistry:
    def __init__(self, db_path: str = "subject_registry.db"):
        self.db_path = db_path
        with closing(sqlite3.connect(self.db_path)) as conn:
            conn.executescript(SCHEMA)
            conn.commit()

    def _conn(self):
        return closing(sqlite3.connect(self.db_path))

    def resolve_or_create(self, fingerprints: List[str], entity_types: Optional[dict] = None) -> str:
        """Given a set of PII fingerprints found in one chunk, resolve them
        to a single data_subject_id. If any fingerprint is already known,
        reuse that subject_id (and link the new fingerprints to it too --
        this is how "email in doc A" + "phone in doc B" end up correctly
        merged into one subject once a doc contains both). If none are
        known, mint a new subject_id.
        """
        entity_types = entity_types or {}
        if not fingerprints:
            return None

        with self._conn() as conn:
            cur = conn.cursor()
            existing_subject = None
            for fp in fingerprints:
                row = cur.execute(
                    "SELECT subject_id FROM fingerprints WHERE fingerprint = ?", (fp,)
                ).fetchone()
                if row:
                    existing_subject = row[0]
                    break

            subject_id = existing_subject or str(uuid.uuid4())

            if not existing_subject:
                cur.execute("INSERT OR IGNORE INTO subjects (subject_id) VALUES (?)", (subject_id,))

            for fp in fingerprints:
                cur.execute(
                    "INSERT OR IGNORE INTO fingerprints (fingerprint, subject_id, entity_type) VALUES (?, ?, ?)",
                    (fp, subject_id, entity_types.get(fp, "unknown")),
                )
            conn.commit()
            return subject_id

    def find_subject_by_fingerprint(self, fingerprint: str) -> Optional[str]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT subject_id FROM fingerprints WHERE fingerprint = ?", (fingerprint,)
            ).fetchone()
            return row[0] if row else None

    def mark_erased(self, subject_id: str):
        with self._conn() as conn:
            conn.execute("UPDATE subjects SET status = 'erased' WHERE subject_id = ?", (subject_id,))
            conn.commit()

    def fingerprints_for_subject(self, subject_id: str) -> List[str]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT fingerprint FROM fingerprints WHERE subject_id = ?", (subject_id,)
            ).fetchall()
            return [r[0] for r in rows]
