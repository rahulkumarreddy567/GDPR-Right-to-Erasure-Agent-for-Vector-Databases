"""
audit_log.py

Append-only, hash-chained audit log. Every entry includes the SHA-256 hash
of the previous entry, so any retroactive edit or deletion breaks the
chain and is detectable -- this is what turns "we deleted it, trust us"
into "we deleted it, and here is cryptographic proof the log wasn't
altered afterwards," which is the actual bar GDPR Article 5(2)
(accountability) and Article 30 (records of processing) expect.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Optional


GENESIS_HASH = "0" * 64


class AuditLog:
    def __init__(self, path: str = "audit_log.jsonl"):
        self.path = path

    def _last_hash(self) -> str:
        if not os.path.exists(self.path) or os.path.getsize(self.path) == 0:
            return GENESIS_HASH
        last_line = None
        with open(self.path, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    last_line = line
        if not last_line:
            return GENESIS_HASH
        return json.loads(last_line)["entry_hash"]

    def record(self, action: str, subject_id: str, details: dict) -> dict:
        prev_hash = self._last_hash()
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,  # e.g. "erasure_executed", "erasure_flagged_for_review", "ingest_tagged"
            "subject_id": subject_id,
            "details": details,
            "prev_hash": prev_hash,
        }
        payload = json.dumps(entry, sort_keys=True)
        entry_hash = hashlib.sha256((prev_hash + payload).encode("utf-8")).hexdigest()
        entry["entry_hash"] = entry_hash

        with open(self.path, "a") as f:
            f.write(json.dumps(entry) + "\n")

        return entry

    def verify_chain(self) -> bool:
        """Replays the whole log and confirms no entry was tampered with."""
        if not os.path.exists(self.path):
            return True
        prev_hash = GENESIS_HASH
        with open(self.path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                entry = json.loads(line)
                claimed_hash = entry.pop("entry_hash")
                payload = json.dumps(entry, sort_keys=True)
                recomputed = hashlib.sha256((prev_hash + payload).encode("utf-8")).hexdigest()
                if recomputed != claimed_hash:
                    return False
                prev_hash = claimed_hash
        return True

    def read_all(self) -> list:
        if not os.path.exists(self.path):
            return []
        with open(self.path) as f:
            return [json.loads(line) for line in f if line.strip()]
