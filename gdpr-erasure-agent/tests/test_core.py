import os
import sys
import shutil
import hashlib
import numpy as np
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src import pii_scanner
from src.vector_store import VectorStore
from src.subject_registry import SubjectRegistry
from src.audit_log import AuditLog
from src.erasure_agent import ErasureAgent

TEST_DIR = os.path.join(os.path.dirname(__file__), "_test_data")


@pytest.fixture(autouse=True)
def clean_dir():
    if os.path.exists(TEST_DIR):
        shutil.rmtree(TEST_DIR)
    os.makedirs(TEST_DIR)
    yield
    shutil.rmtree(TEST_DIR, ignore_errors=True)


def test_email_detection():
    result = pii_scanner.scan("contact me at test.user@example.com please")
    types = [m.entity_type for m in result.matches]
    assert "EMAIL" in types


def test_same_value_same_fingerprint():
    r1 = pii_scanner.scan("Email: a@b.com")
    r2 = pii_scanner.scan("email: A@B.com")  # different case, should normalize
    assert r1.fingerprints == r2.fingerprints


def test_vector_store_add_and_erase():
    vs = VectorStore(dim=16, index_path=f"{TEST_DIR}/v.faiss", db_path=f"{TEST_DIR}/c.db")
    vec = np.random.rand(16).astype("float32")
    cid = vs.add(vec, doc_id="d1", subject_ids=["subj-1"], source_path="x.txt", text_preview="preview")
    assert vs.stats()["total_chunks"] == 1
    removed = vs.erase_subject("subj-1")
    assert removed == [cid]
    assert vs.stats()["total_chunks"] == 0


def test_erasure_agent_requires_hard_identifier():
    vs = VectorStore(dim=16, index_path=f"{TEST_DIR}/v2.faiss", db_path=f"{TEST_DIR}/c2.db")
    registry = SubjectRegistry(db_path=f"{TEST_DIR}/reg2.db")
    audit = AuditLog(path=f"{TEST_DIR}/audit2.jsonl")
    agent = ErasureAgent(vs, registry, audit)

    decision = agent.request_erasure("random text with no PII")
    assert decision.status == "not_found"


def test_audit_chain_detects_tampering():
    audit = AuditLog(path=f"{TEST_DIR}/audit3.jsonl")
    audit.record(action="test", subject_id="s1", details={"x": 1})
    audit.record(action="test", subject_id="s1", details={"x": 2})
    assert audit.verify_chain() is True

    # tamper with the file directly
    with open(f"{TEST_DIR}/audit3.jsonl") as f:
        lines = f.readlines()
    lines[0] = lines[0].replace('"x": 1', '"x": 999')
    with open(f"{TEST_DIR}/audit3.jsonl", "w") as f:
        f.writelines(lines)

    assert audit.verify_chain() is False
