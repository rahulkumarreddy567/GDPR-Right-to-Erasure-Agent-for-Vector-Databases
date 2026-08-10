"""
api/main.py

FastAPI surface for the GDPR erasure agent. Swap `embed_fn` for a real
embedding model (sentence-transformers, OpenAI, Anthropic, Voyage, etc.)
in production -- a deterministic hash-based stub is used here so the
service runs with zero external API calls / model downloads for demo and
CI purposes.
"""

from __future__ import annotations

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import hashlib
import numpy as np
from fastapi import FastAPI
from pydantic import BaseModel

from src.audit_log import AuditLog
from src.erasure_agent import ErasureAgent
from src.ingest import IngestionPipeline
from src.subject_registry import SubjectRegistry
from src.vector_store import VectorStore

DIM = 128


def stub_embed(text: str) -> np.ndarray:
    """Deterministic pseudo-embedding for demo purposes only.
    Replace with a real embedding model in production.
    """
    h = hashlib.sha256(text.encode("utf-8")).digest()
    rng = np.random.default_rng(int.from_bytes(h[:8], "little"))
    return rng.standard_normal(DIM).astype("float32")


vector_store = VectorStore(dim=DIM, index_path="data/vectors.faiss", db_path="data/chunks.db")
registry = SubjectRegistry(db_path="data/subject_registry.db")
audit_log = AuditLog(path="data/audit_log.jsonl")

pipeline = IngestionPipeline(vector_store, registry, stub_embed, audit_log=audit_log)
agent = ErasureAgent(vector_store, registry, audit_log)

app = FastAPI(title="GDPR Right-to-Erasure Agent for Vector Databases")


class IngestRequest(BaseModel):
    text: str
    source_path: str = "uploaded_document"


class ErasureRequest(BaseModel):
    identifier: str  # email, phone, or full name mentioned in a document


@app.post("/ingest")
def ingest(req: IngestRequest):
    return pipeline.ingest_document(req.text, source_path=req.source_path)


@app.post("/erase")
def erase(req: ErasureRequest):
    decision = agent.request_erasure(req.identifier)
    return {
        "status": decision.status,
        "subject_id": decision.subject_id,
        "chunks_removed": decision.chunks_removed,
        "reason": decision.reason,
        "report": decision.report,
    }


@app.get("/audit-log")
def get_audit_log():
    return {"chain_valid": audit_log.verify_chain(), "entries": audit_log.read_all()}


@app.get("/stats")
def stats():
    return vector_store.stats()
