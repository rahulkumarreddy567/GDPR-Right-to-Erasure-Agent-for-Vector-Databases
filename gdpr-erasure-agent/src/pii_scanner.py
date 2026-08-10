"""
pii_scanner.py

Detects personally identifiable information (PII) inside a text chunk BEFORE
it gets embedded into a vector store, and produces a stable "fingerprint"
for each identifier found (email, phone, IBAN, national ID, etc).

The fingerprint is a salted hash of the normalized identifier value. It is
used downstream to link chunks to a `data_subject_id` in the subject
registry, WITHOUT storing the raw PII value itself in the vector store's
metadata (defense in depth: even the metadata DB is not a second copy of
the PII).

This is intentionally dependency-light (pure regex + optional spaCy NER for
person names) so it runs anywhere, including air-gapped / sandboxed
environments used for CI.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import List, Optional

# Salt should come from a secrets manager in production. Kept as a constant
# here for reproducibility in the demo / tests.
FINGERPRINT_SALT = "gdpr-erasure-agent-v1"

PII_PATTERNS = {
    "EMAIL": re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
    "PHONE_FR": re.compile(r"(?:(?:\+33|0)[1-9](?:[\s.-]?\d{2}){4})"),
    "PHONE_INTL": re.compile(r"\+\d{1,3}[\s.-]?\(?\d{1,4}\)?(?:[\s.-]?\d{2,4}){2,4}"),
    "IBAN": re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b"),
    "CREDIT_CARD": re.compile(r"\b(?:\d[ -]*?){13,16}\b"),
    "FR_NIR": re.compile(r"\b[12]\d{2}(0[1-9]|1[0-2])\d{2}\d{3}\d{3}\d{2}\b"),  # French social security number
    "PASSPORT_FR": re.compile(r"\b\d{2}[A-Z]{2}\d{5}\b"),
}

try:
    import spacy  # type: ignore

    _NLP = spacy.load("en_core_web_sm")
    _HAS_SPACY = True
except Exception:
    _NLP = None
    _HAS_SPACY = False


@dataclass
class PIIMatch:
    entity_type: str
    value: str
    start: int
    end: int
    fingerprint: str
    confidence: float = 1.0


@dataclass
class ScanResult:
    text: str
    matches: List[PIIMatch] = field(default_factory=list)

    @property
    def fingerprints(self) -> List[str]:
        # de-duplicated, order-preserving
        seen = set()
        out = []
        for m in self.matches:
            if m.fingerprint not in seen:
                seen.add(m.fingerprint)
                out.append(m.fingerprint)
        return out

    @property
    def has_pii(self) -> bool:
        return len(self.matches) > 0


def _fingerprint(value: str) -> str:
    normalized = re.sub(r"\s+", "", value).lower()
    return hashlib.sha256((FINGERPRINT_SALT + normalized).encode("utf-8")).hexdigest()[:24]


def _regex_scan(text: str) -> List[PIIMatch]:
    matches: List[PIIMatch] = []
    for entity_type, pattern in PII_PATTERNS.items():
        for m in pattern.finditer(text):
            value = m.group(0)
            # cheap sanity filter for CREDIT_CARD to cut down on false positives
            # from plain long numbers (e.g. invoice numbers)
            if entity_type == "CREDIT_CARD":
                digits = re.sub(r"[ -]", "", value)
                if not (13 <= len(digits) <= 16):
                    continue
            matches.append(
                PIIMatch(
                    entity_type=entity_type,
                    value=value,
                    start=m.start(),
                    end=m.end(),
                    fingerprint=_fingerprint(value),
                    confidence=0.9,
                )
            )
    return matches


_NAME_FALLBACK_PATTERN = re.compile(r"\b[A-Z][a-z]+(?:-[A-Z][a-z]+)?\s[A-Z][a-z]+(?:-[A-Z][a-z]+)?\b")

# common non-name capitalized bigrams to suppress obvious false positives
# from the regex fallback (real deployments should use spaCy/a transformer
# NER model instead -- this fallback exists so the project runs with zero
# model downloads for demo/CI purposes)
_NAME_FALLBACK_STOPWORDS = {"United States", "New York", "Premium Plan"}


def _regex_name_fallback_scan(text: str) -> List[PIIMatch]:
    out = []
    for m in _NAME_FALLBACK_PATTERN.finditer(text):
        value = m.group(0)
        if value in _NAME_FALLBACK_STOPWORDS:
            continue
        out.append(
            PIIMatch(
                entity_type="PERSON_NAME",
                value=value,
                start=m.start(),
                end=m.end(),
                fingerprint=_fingerprint(value),
                confidence=0.6,  # weaker than spaCy NER -- regex has no grammatical context
            )
        )
    return out


def _spacy_person_scan(text: str) -> List[PIIMatch]:
    if not _HAS_SPACY:
        return _regex_name_fallback_scan(text)
    doc = _NLP(text)
    out = []
    for ent in doc.ents:
        if ent.label_ == "PERSON":
            out.append(
                PIIMatch(
                    entity_type="PERSON_NAME",
                    value=ent.text,
                    start=ent.start_char,
                    end=ent.end_char,
                    fingerprint=_fingerprint(ent.text),
                    confidence=0.75,  # names are noisier than regex-matched identifiers
                )
            )
    return out


def scan(text: str, include_names: bool = True) -> ScanResult:
    """Scan a chunk of text for PII. Returns matches + stable fingerprints.

    `include_names` requires spaCy + en_core_web_sm to be installed; if not
    available, name detection silently degrades to regex-only identifiers
    (email/phone/IBAN/national IDs), which is still enough to build a
    working data-subject linkage for most real-world documents (contracts,
    support tickets, medical intake forms almost always carry an email or
    phone number alongside the name).
    """
    matches = _regex_scan(text)
    if include_names:
        matches.extend(_spacy_person_scan(text))
    return ScanResult(text=text, matches=matches)


def redact(text: str, matches: Optional[List[PIIMatch]] = None) -> str:
    """Return a redacted copy of text, e.g. for safe logging/debugging."""
    matches = matches if matches is not None else scan(text).matches
    out = text
    for m in sorted(matches, key=lambda x: -x.start):
        out = out[: m.start] + f"[REDACTED:{m.entity_type}]" + out[m.end :]
    return out
