"""
run_demo.py

End-to-end demo, no external services required:
  1. Ingest 3 fake documents (2 mention the same person under different
     contact details, 1 mentions someone else)
  2. Show that the same person's chunks got linked to ONE subject_id
     across documents
  3. Fire a GDPR erasure request using just an email address
  4. Prove the vectors are actually gone (search before/after)
  5. Print the tamper-evident audit log and verify its hash chain
"""

import sys
import os
import shutil
import hashlib
import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.vector_store import VectorStore
from src.subject_registry import SubjectRegistry
from src.audit_log import AuditLog
from src.ingest import IngestionPipeline
from src.erasure_agent import ErasureAgent

DIM = 128
DATA_DIR = os.path.join(os.path.dirname(__file__), "_demo_data")


def stub_embed(text: str) -> np.ndarray:
    h = hashlib.sha256(text.encode("utf-8")).digest()
    rng = np.random.default_rng(int.from_bytes(h[:8], "little"))
    return rng.standard_normal(DIM).astype("float32")


def main():
    if os.path.exists(DATA_DIR):
        shutil.rmtree(DATA_DIR)
    os.makedirs(DATA_DIR)

    vs = VectorStore(dim=DIM, index_path=f"{DATA_DIR}/vectors.faiss", db_path=f"{DATA_DIR}/chunks.db")
    registry = SubjectRegistry(db_path=f"{DATA_DIR}/subjects.db")
    audit = AuditLog(path=f"{DATA_DIR}/audit_log.jsonl")
    pipeline = IngestionPipeline(vs, registry, stub_embed, audit_log=audit)
    agent = ErasureAgent(vs, registry, audit)

    doc_a = """
    Customer support ticket #4471. Customer Jean Dupont (jean.dupont@mail.fr)
    reported a login issue on 2026-06-02. Phone on file: +33 6 12 34 56 78.
    Issue resolved by resetting password.
    """

    doc_b = """
    Follow-up call notes: spoke with jean.dupont@mail.fr regarding invoice
    #8821. Customer confirmed billing address is correct. No further action.
    """

    doc_c = """
    Onboarding form for Marie Curie (marie.curie@example.com), phone
    +33 7 98 76 54 32. Account created 2026-01-15. Plan: Premium.
    """

    print("=== INGESTING 3 DOCUMENTS ===")
    r1 = pipeline.ingest_document(doc_a, source_path="ticket_4471.txt")
    r2 = pipeline.ingest_document(doc_b, source_path="followup_notes.txt")
    r3 = pipeline.ingest_document(doc_c, source_path="onboarding_form.txt")

    subj_a = next((c["subject_id"] for c in r1["chunk_reports"] if c["subject_id"]), None)
    subj_b = next((c["subject_id"] for c in r2["chunk_reports"] if c["subject_id"]), None)
    subj_c = next((c["subject_id"] for c in r3["chunk_reports"] if c["subject_id"]), None)

    print(f"doc_a subject_id: {subj_a}")
    print(f"doc_b subject_id: {subj_b}  <-- should MATCH doc_a (same email)")
    print(f"doc_c subject_id: {subj_c}  <-- should be DIFFERENT person\n")

    assert subj_a == subj_b, "same email across two docs should resolve to the SAME subject_id"
    assert subj_a != subj_c, "different person should get a DIFFERENT subject_id"
    print("Subject resolution across documents: PASSED\n")

    print("=== STATE BEFORE ERASURE ===")
    print(vs.stats())
    chunks_before = vs.chunk_ids_for_subject(subj_a)
    print(f"Chunks tagged to Jean Dupont before erasure: {chunks_before}\n")

    print("=== ERASURE REQUEST: 'jean.dupont@mail.fr' ===")
    decision = agent.request_erasure("jean.dupont@mail.fr")
    print(f"Status: {decision.status}")
    print(f"Chunks removed: {decision.chunks_removed}")
    print(f"Report: {decision.report}\n")

    print("=== STATE AFTER ERASURE ===")
    print(vs.stats())
    chunks_after = vs.chunk_ids_for_subject(subj_a)
    print(f"Chunks still tagged to Jean Dupont after erasure: {chunks_after}")
    assert chunks_after == [], "erasure must leave zero chunks for this subject"
    print("Vector-level deletion: VERIFIED\n")

    print("=== MARIE CURIE'S DATA UNTOUCHED ===")
    chunks_marie = vs.chunk_ids_for_subject(subj_c)
    print(f"Chunks still tagged to Marie Curie: {chunks_marie}")
    assert len(chunks_marie) > 0, "erasing one subject must not affect other subjects"
    print("Isolation between subjects: VERIFIED\n")

    print("=== AUDIT LOG ===")
    for entry in audit.read_all():
        print(entry)
    print(f"\nAudit chain tamper-check: {'VALID' if audit.verify_chain() else 'BROKEN'}")

    print("\n=== AMBIGUOUS CASE: name-only request ===")
    decision2 = agent.request_erasure("Marie Curie")
    print(f"Status: {decision2.status}")
    print(f"Reason: {decision2.reason}")
    assert decision2.status == "flagged_for_review", "name-only match must be flagged, not auto-deleted"
    print("Safety guard (no auto-delete on weak match): VERIFIED")


if __name__ == "__main__":
    main()
