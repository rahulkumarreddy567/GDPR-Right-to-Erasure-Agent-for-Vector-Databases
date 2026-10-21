# GDPR Right-to-Erasure Agent for Vector Databases

An auditable, deterministic deletion layer for RAG systems that store
personal data in vector databases.

## The problem

GDPR Article 17 gives data subjects a right to erasure. Deleting a row from a
relational table is straightforward, but a RAG pipeline usually turns source
documents into chunks and opaque embedding vectors. Without a link from each
vector back to the person it concerns, a deletion request can require
rebuilding an entire index or, worse, can be handled incompletely.

This project tags personal data during ingestion, before embedding. Each
matching identifier is converted into a salted fingerprint and associated
with a stable `data_subject_id`. The resulting subject-to-chunk index makes
erasure surgical, verifiable, and auditable.

## What it does

1. **Scans** each document chunk for email addresses, phone numbers, IBANs,
   payment-card-like values, French national identifiers, French passports,
   and person names.
2. **Fingerprints** detected identifiers without storing the raw identifier
   in vector metadata.
3. **Links** fingerprints to a stable subject ID in a SQLite registry.
4. **Stores** embeddings in a FAISS `IndexIDMap2` index, with chunk metadata
   in SQLite.
5. **Resolves and verifies** erasure requests. Ambiguous requests and
   name-only matches are flagged for human review.
6. **Deletes** all FAISS vectors and metadata rows tagged for the confirmed
   subject.
7. **Proves** the action with an append-only, SHA-256 hash-chained audit log.

The deletion decision is deterministic Python code. An optional LLM hook can
draft a human-readable report after deletion, but it never decides whether
the deletion should happen and receives no raw PII.

## Architecture

```text
document
   |
   v
PII scanner -- salted fingerprints --> subject registry
   |                                      |
   v                                      v
chunk + subject_id -- embed --> FAISS vectors + SQLite metadata
                                      |
                                      v
                         erasure agent: resolve -> verify -> delete -> prove
                                                              |
                                                              v
                                                   hash-chained audit log
```

## Repository layout

The Python project is kept in [`gdpr-erasure-agent/`](./gdpr-erasure-agent/).

```text
gdpr-erasure-agent/
├── src/
│   ├── audit_log.py        Hash-chained append-only audit trail
│   ├── erasure_agent.py    Resolve, verify, execute, and prove erasure
│   ├── ingest.py           Chunk, scan, tag, embed, and store pipeline
│   ├── pii_scanner.py      Regex and optional spaCy PII detection
│   ├── subject_registry.py Fingerprint-to-subject SQLite registry
│   └── vector_store.py     FAISS index and chunk metadata store
├── api/main.py             FastAPI service
├── demo/run_demo.py        End-to-end demo with no external services
├── tests/test_core.py      Unit tests
├── requirements.txt        Runtime and test dependencies
└── README.md               Project-specific technical notes
```

## Requirements

- Python 3.10 or newer
- Windows, macOS, or Linux
- A virtual environment is recommended

The default demo uses a deterministic hash-based embedding stub. It does not
download a model or call an external API.

## Installation

From the repository root:

```powershell
cd .\gdpr-erasure-agent
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

If PowerShell execution policies prevent activation, use the virtual
environment's interpreter directly:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

## Run the demo

```powershell
cd .\gdpr-erasure-agent
python .\demo\run_demo.py
```

The demo:

- ingests three documents;
- confirms that two documents for the same email resolve to one subject;
- deletes that subject's vectors;
- verifies that another subject's vectors remain;
- verifies the audit hash chain; and
- confirms that a name-only request is flagged instead of auto-deleted.

The demo writes temporary files under `demo/_demo_data/`. They are ignored by
Git and are recreated on each run.

## Run tests

```powershell
cd .\gdpr-erasure-agent
python -m pytest .\tests -v
```

The test suite covers PII detection, fingerprint normalization, vector
deletion, unsafe-identifier handling, and audit-log tamper detection.

## Run the API

```powershell
cd .\gdpr-erasure-agent
python -m uvicorn api.main:app --reload
```

The service exposes:

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `GET` | `/` | Service status and useful links |
| `GET` | `/health` | Lightweight health check |
| `POST` | `/ingest` | Scan and ingest a document |
| `POST` | `/erase` | Resolve and process an erasure request |
| `GET` | `/audit-log` | Return the audit entries and chain status |
| `GET` | `/stats` | Return vector and metadata counts |

Example requests:

```powershell
Invoke-RestMethod http://localhost:8000/ingest `
  -Method Post `
  -ContentType "application/json" `
  -Body '{"text":"Contact: jean.dupont@mail.fr, +33 6 12 34 56 78","source_path":"ticket.txt"}'

Invoke-RestMethod http://localhost:8000/erase `
  -Method Post `
  -ContentType "application/json" `
  -Body '{"identifier":"jean.dupont@mail.fr"}'

Invoke-RestMethod http://localhost:8000/audit-log
```

The API creates runtime data under `gdpr-erasure-agent/data/`, which is
ignored by Git.

## Safety behavior

An erasure request is executed only when a recognized hard identifier
(email, phone, national ID, passport, or similar identifier) resolves to
exactly one subject. The agent returns:

- `executed` when the request is unambiguous and deletion succeeds;
- `flagged_for_review` when multiple subjects match or only a low-confidence
  name match is available; or
- `not_found` when the identifier is unsupported or has no stored match.

The registry keeps the subject's fingerprint records and marks the subject as
`erased`; the vector and chunk metadata records are removed. This preserves
the auditability of the decision without retaining the deleted vector data.

## Optional integrations

### Name detection with spaCy

The scanner falls back to a conservative capitalized-name pattern when spaCy
is unavailable. For improved name detection:

```powershell
python -m pip install spacy
python -m spacy download en_core_web_sm
```

### Production embeddings

Replace `stub_embed` in [`api/main.py`](./gdpr-erasure-agent/api/main.py) or
[`run_demo.py`](./gdpr-erasure-agent/demo/run_demo.py) with the embedding
function used by the application. The PII tagging and erasure logic is
independent of the embedding provider.

## Important limitations

This is a focused reference implementation, not a complete compliance
certification or production deployment:

- The fingerprint salt is intentionally a constant for reproducible tests;
  production deployments must load it from a secrets manager and plan for
  safe rotation.
- PII that spans a chunk boundary can be missed. Production ingestion should
  scan with a sliding window before final chunking.
- Direct identifiers are covered, but indirect or quasi-identifying context
  can still permit re-identification.
- FAISS `IndexIDMap2` is appropriate for this demo and moderate workloads.
  Large deployments need capacity planning, backups, access controls, index
  compaction, and an operational recovery strategy.
- Deleting local vectors does not delete copies held in source systems,
  backups, caches, logs, model-training datasets, or other downstream
  stores. Those systems must participate in the erasure workflow.
- The API uses process-local service objects and is not hardened for
  authentication, authorization, concurrency, or multi-tenant isolation.

Treat the audit log, registry database, vector index, source documents, and
backups as sensitive operational data. Add authentication, authorization,
encryption, secure secret management, retention controls, and monitoring
before handling real personal data.

## License

No license has been declared for this repository yet. Add an explicit
`LICENSE` file before distributing or reusing the project.
