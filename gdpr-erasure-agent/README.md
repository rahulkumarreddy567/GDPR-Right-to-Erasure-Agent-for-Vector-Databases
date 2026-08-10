# GDPR Right-to-Erasure Agent for Vector Databases

**The problem:** Article 17 of the GDPR gives every person a "right to
erasure" — on request, a company must delete their personal data. This is
straightforward for a row in a SQL table. It is *not* straightforward once
that data has been chunked and embedded into a vector store for RAG: the
resulting float vectors have no inherent link back to "this belongs to
Jean Dupont," so most RAG pipelines built today have no reliable way to
fulfill an erasure request without re-processing (or blindly wiping) the
entire index. Every company running RAG over customer support tickets,
patient records, HR documents, or CRM notes in the EU has this exposure
right now.

**What this project does:** tags personal data at the moment of ingestion
— *before* it becomes an opaque vector — so an erasure request becomes a
fast, provable, surgical delete instead of an unsolved problem.

## Architecture

```
                 ┌─────────────┐
   documents ──▶ │ PII Scanner │  regex + name NER, produces salted
                 └──────┬──────┘  fingerprints (never stores raw PII)
                        │
                        ▼
                 ┌─────────────────┐
                 │ Subject Registry│  fingerprint → stable data_subject_id
                 └──────┬──────────┘  (links the same person across docs)
                        │
                        ▼
                 ┌─────────────┐        ┌────────────┐
   chunk text ──▶│  Embedder   │──────▶ │VectorStore │  FAISS IndexIDMap2 +
                 └─────────────┘  vector│(FAISS +    │  SQLite metadata,
                                        │ SQLite)    │  tagged with subject_id
                                        └─────┬──────┘
                                              │
                          erasure request     │  find + remove_ids()
                          ("delete jean@..")  │
                                              ▼
                                    ┌────────────────┐
                                    │ Erasure Agent   │  resolve → verify →
                                    │ (decision core) │  execute → prove
                                    └────────┬────────┘
                                             │
                                             ▼
                                    ┌────────────────┐
                                    │ Hash-chained    │  tamper-evident,
                                    │ Audit Log       │  regulator-ready
                                    └────────────────┘
```

### Why this is "agentic" and not just a delete script

The erasure agent has to make a judgment call before an **irreversible**
action:

1. **Resolve** — turn a free-text identifier (email, phone, name) into a
   `data_subject_id` via the fingerprint registry.
2. **Verify** — if the identifier is ambiguous (matches 0, matches >1
   subjects, or only matches on a low-confidence signal like a bare name),
   it refuses to auto-delete and flags the request for human review
   instead. Deleting the wrong person's data is a worse failure mode than
   a slower erasure process.
3. **Execute** — only on an unambiguous match against a hard identifier
   (email/phone/national ID), it deletes the vectors + metadata.
4. **Prove** — writes a SHA-256 hash-chained audit log entry and generates
   a human-readable compliance report (pluggable LLM call) a DPO could
   hand to a regulator.

Deliberate design choice worth stating in interviews: the *decision* of
whether to delete is deterministic Python, not an LLM guess. The LLM (if
wired in) only drafts the final report, and only sees fingerprints/counts/
entity-type labels — never raw PII. "Agentic" here means "software that
reasons about and safely executes an irreversible action," not "let the
model decide."

## Project layout

```
src/
  pii_scanner.py       regex (+ optional spaCy NER) PII detection & fingerprinting
  subject_registry.py  fingerprint -> data_subject_id, SQLite-backed
  vector_store.py       FAISS IndexIDMap2 wrapper with true per-vector deletion
  ingest.py             chunk -> scan -> tag -> embed -> store pipeline
  erasure_agent.py      the resolve/verify/execute/prove decision core
  audit_log.py          hash-chained, tamper-evident audit trail
api/
  main.py               FastAPI: POST /ingest, POST /erase, GET /audit-log
demo/
  run_demo.py            end-to-end scripted demo, zero external services
tests/
  test_core.py           unit tests (PII detection, deletion, tamper detection)
```

## Running it

```bash
pip install -r requirements.txt

# scripted end-to-end demo (ingest 3 docs, erase one person, verify audit log)
python demo/run_demo.py

# unit tests
pytest tests/ -v

# API server
uvicorn api.main:app --reload
# then:
curl -X POST localhost:8000/ingest -H "Content-Type: application/json" \
     -d '{"text": "Contact: jean.dupont@mail.fr, +33 6 12 34 56 78"}'
curl -X POST localhost:8000/erase -H "Content-Type: application/json" \
     -d '{"identifier": "jean.dupont@mail.fr"}'
curl localhost:8000/audit-log
```

The demo uses a deterministic hash-based stub embedder so it runs with
**zero external API calls or model downloads**. Swap `stub_embed` in
`api/main.py` / `demo/run_demo.py` for a real embedding model
(sentence-transformers, OpenAI, Anthropic, Voyage) in production — nothing
else in the pipeline needs to change, since tagging happens independently
of which embedder you use.

## Known limitations (say these out loud in interviews — it shows judgment)

- **Name detection**: falls back to a simple capitalized-bigram regex when
  spaCy isn't installed. Production deployments should use spaCy or a
  transformer NER model for real name detection — this is flagged as
  low-confidence on purpose and never triggers auto-deletion on its own.
- **Chunk boundary leakage**: if a chunk is split awkwardly, a PII value
  could span a chunk boundary and be missed. A production system would
  scan on a sliding window before final chunking.
- **Re-identification via context**: even with all direct identifiers
  removed, an adjacent chunk (e.g. "the customer who called about invoice
  #8821") could be indirectly linkable. This project handles direct
  identifiers; indirect/quasi-identifier linkage is a harder open problem
  worth mentioning as future work.
- **FAISS index type**: `IndexIDMap2` over `IndexFlatL2` was chosen because
  it's the simplest FAISS index that supports true ID-based removal. For
  large-scale production (millions of vectors) you'd want `IndexIVFFlat`
  wrapped the same way, with periodic index compaction after heavy churn.

## Why this project (for recruiters / interviewers)

RAG-in-production and the EU AI Act / GDPR compliance burden are both very
current, very real problems — this sits exactly at that intersection,
which is not a saturated portfolio category. It's directly relevant to any
company running RAG over customer or patient data (banks, healthtech,
insurance), demonstrates production-engineering judgment (irreversible
actions need safety rails, not just "call the LLM"), and gives a concrete,
demoable, testable artifact rather than a slide deck.
