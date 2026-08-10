"""
vector_store.py

A FAISS index wrapped so that every vector is addressable by a stable
integer chunk_id (via IndexIDMap2, which supports true removal -- plain
IndexFlatL2 does not support deleting individual vectors).

A parallel SQLite table stores chunk metadata:
    chunk_id -> { doc_id, subject_ids (JSON list), source_path, created_at }

This is the piece that makes erasure actually possible: given a
data_subject_id, we can find every chunk_id tagged with it and remove the
vector from FAISS AND the metadata row in one transaction, instead of
"we embedded it and now it's gone forever into a black box."
"""

from __future__ import annotations

import json
import sqlite3
import numpy as np
import faiss
from contextlib import closing
from dataclasses import dataclass
from typing import List, Optional


SCHEMA = """
CREATE TABLE IF NOT EXISTS chunks (
    chunk_id INTEGER PRIMARY KEY,
    doc_id TEXT NOT NULL,
    subject_ids TEXT NOT NULL,   -- JSON list of data_subject_id strings
    source_path TEXT,
    text_preview TEXT,           -- short, non-PII preview only (first N chars, redacted upstream)
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
"""


@dataclass
class ChunkRecord:
    chunk_id: int
    doc_id: str
    subject_ids: List[str]
    source_path: str
    text_preview: str


class VectorStore:
    def __init__(self, dim: int, index_path: str = "vectors.faiss", db_path: str = "chunks.db"):
        self.dim = dim
        self.index_path = index_path
        self.db_path = db_path

        try:
            self.index = faiss.read_index(index_path)
        except Exception:
            base = faiss.IndexFlatL2(dim)
            self.index = faiss.IndexIDMap2(base)

        with closing(sqlite3.connect(self.db_path)) as conn:
            conn.executescript(SCHEMA)
            conn.commit()

        self._next_id = self._load_next_id()

    def _load_next_id(self) -> int:
        with closing(sqlite3.connect(self.db_path)) as conn:
            row = conn.execute("SELECT MAX(chunk_id) FROM chunks").fetchone()
            return (row[0] or -1) + 1

    def add(self, vector: np.ndarray, doc_id: str, subject_ids: List[str], source_path: str, text_preview: str) -> int:
        chunk_id = self._next_id
        self._next_id += 1

        vec = np.asarray(vector, dtype="float32").reshape(1, -1)
        ids = np.array([chunk_id], dtype="int64")
        self.index.add_with_ids(vec, ids)

        with closing(sqlite3.connect(self.db_path)) as conn:
            conn.execute(
                "INSERT INTO chunks (chunk_id, doc_id, subject_ids, source_path, text_preview) VALUES (?, ?, ?, ?, ?)",
                (chunk_id, doc_id, json.dumps(subject_ids), source_path, text_preview),
            )
            conn.commit()

        return chunk_id

    def search(self, query_vector: np.ndarray, k: int = 5) -> List[ChunkRecord]:
        vec = np.asarray(query_vector, dtype="float32").reshape(1, -1)
        distances, ids = self.index.search(vec, k)
        results = []
        with closing(sqlite3.connect(self.db_path)) as conn:
            for cid in ids[0]:
                if cid == -1:
                    continue
                row = conn.execute(
                    "SELECT chunk_id, doc_id, subject_ids, source_path, text_preview FROM chunks WHERE chunk_id = ?",
                    (int(cid),),
                ).fetchone()
                if row:
                    results.append(
                        ChunkRecord(
                            chunk_id=row[0],
                            doc_id=row[1],
                            subject_ids=json.loads(row[2]),
                            source_path=row[3],
                            text_preview=row[4],
                        )
                    )
        return results

    def chunk_ids_for_subject(self, subject_id: str) -> List[int]:
        with closing(sqlite3.connect(self.db_path)) as conn:
            rows = conn.execute("SELECT chunk_id, subject_ids FROM chunks").fetchall()
        return [cid for cid, sids_json in rows if subject_id in json.loads(sids_json)]

    def erase_subject(self, subject_id: str) -> List[int]:
        """Hard-delete every vector + metadata row tagged with subject_id.
        Returns the list of chunk_ids that were removed (for the audit log).
        """
        chunk_ids = self.chunk_ids_for_subject(subject_id)
        if not chunk_ids:
            return []

        id_array = np.array(chunk_ids, dtype="int64")
        self.index.remove_ids(id_array)

        with closing(sqlite3.connect(self.db_path)) as conn:
            conn.executemany("DELETE FROM chunks WHERE chunk_id = ?", [(cid,) for cid in chunk_ids])
            conn.commit()

        return chunk_ids

    def save(self):
        faiss.write_index(self.index, self.index_path)

    def stats(self) -> dict:
        with closing(sqlite3.connect(self.db_path)) as conn:
            total = conn.execute("SELECT COUNT(*) FROM chunks").fetchone()[0]
        return {"total_chunks": total, "index_ntotal": self.index.ntotal}
