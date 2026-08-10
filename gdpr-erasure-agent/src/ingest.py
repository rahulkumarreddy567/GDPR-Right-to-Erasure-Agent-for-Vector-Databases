"""
ingest.py

The ingestion pipeline every RAG project already has -- except each chunk
gets scanned for PII and tagged with a data_subject_id BEFORE it's embedded.
This is the fix point: once a vector exists with no link back to a person,
erasure is nearly impossible. Tag at ingest time and erasure becomes a
simple lookup + delete.
"""

from __future__ import annotations

import uuid
from typing import Callable, List

from . import pii_scanner
from .subject_registry import SubjectRegistry
from .vector_store import VectorStore


def chunk_text(text: str, chunk_size: int = 500, overlap: int = 50) -> List[str]:
    chunks = []
    start = 0
    while start < len(text):
        end = start + chunk_size
        chunks.append(text[start:end])
        start = end - overlap
    return [c for c in chunks if c.strip()]


class IngestionPipeline:
    def __init__(
        self,
        vector_store: VectorStore,
        registry: SubjectRegistry,
        embed_fn: Callable[[str], "np.ndarray"],
        audit_log=None,
    ):
        self.vector_store = vector_store
        self.registry = registry
        self.embed_fn = embed_fn
        self.audit_log = audit_log

    def ingest_document(self, text: str, source_path: str, doc_id: str = None) -> dict:
        doc_id = doc_id or str(uuid.uuid4())
        chunks = chunk_text(text)

        chunk_reports = []
        for chunk in chunks:
            scan_result = pii_scanner.scan(chunk)

            subject_ids = []
            if scan_result.has_pii:
                entity_types = {m.fingerprint: m.entity_type for m in scan_result.matches}
                subject_id = self.registry.resolve_or_create(scan_result.fingerprints, entity_types)
                subject_ids = [subject_id]

            vector = self.embed_fn(chunk)
            preview = pii_scanner.redact(chunk, scan_result.matches)[:120]

            chunk_id = self.vector_store.add(
                vector=vector,
                doc_id=doc_id,
                subject_ids=subject_ids,
                source_path=source_path,
                text_preview=preview,
            )

            if self.audit_log and subject_ids:
                self.audit_log.record(
                    action="ingest_tagged",
                    subject_id=subject_ids[0],
                    details={"chunk_id": chunk_id, "doc_id": doc_id, "entity_types": list(entity_types.values())},
                )

            chunk_reports.append(
                {
                    "chunk_id": chunk_id,
                    "pii_found": scan_result.has_pii,
                    "entity_types": [m.entity_type for m in scan_result.matches],
                    "subject_id": subject_ids[0] if subject_ids else None,
                }
            )

        self.vector_store.save()
        return {"doc_id": doc_id, "chunks_ingested": len(chunks), "chunk_reports": chunk_reports}
