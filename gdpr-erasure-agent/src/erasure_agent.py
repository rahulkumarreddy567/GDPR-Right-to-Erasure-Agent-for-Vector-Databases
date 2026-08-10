"""
erasure_agent.py

This is the "agent" in the project: not a chatbot wrapper, but a piece of
software that has to make a judgment call before taking an irreversible
action (permanently deleting vectors), and has to be able to explain and
prove what it did afterwards.

Flow for an erasure request (e.g. "delete all data for jean.dupont@mail.fr"):

  1. RESOLVE   -- turn the identifier into PII fingerprints, look up subject_id(s)
  2. VERIFY    -- if the identifier matches >1 subject, or 0 subjects, or the
                  match confidence is low (e.g. fuzzy name match only), do
                  NOT auto-delete. Flag for human review instead. Deleting
                  the wrong person's data is a worse failure mode than a
                  slow erasure.
  3. EXECUTE   -- if resolution is unambiguous, erase the vectors + metadata
                  and mark the subject as erased in the registry.
  4. PROVE     -- write a hash-chained audit log entry, and (optionally)
                  call an LLM to turn the raw action into a human-readable
                  compliance report a DPO could hand to a regulator.

The LLM call is intentionally the LAST step and touches no PII directly
(only fingerprints/counts/entity types) -- the reasoning about WHETHER to
delete something is deterministic Python, not an LLM guess. This is a
deliberate design choice worth stating explicitly in interviews: agentic
!= "let the LLM decide," especially for irreversible actions.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, List, Optional

from . import pii_scanner
from .audit_log import AuditLog
from .subject_registry import SubjectRegistry
from .vector_store import VectorStore


@dataclass
class ErasureDecision:
    status: str  # "executed" | "flagged_for_review" | "not_found"
    subject_id: Optional[str]
    chunks_removed: List[int]
    reason: str
    report: Optional[str] = None


class ErasureAgent:
    def __init__(
        self,
        vector_store: VectorStore,
        registry: SubjectRegistry,
        audit_log: AuditLog,
        llm_report_fn: Optional[Callable[[dict], str]] = None,
    ):
        self.vector_store = vector_store
        self.registry = registry
        self.audit_log = audit_log
        # Pluggable: pass a function that calls Claude/GPT to draft the
        # human-readable report. None => falls back to a templated report,
        # so the agent works even with zero LLM calls (useful for testing
        # and for keeping the irreversible-action path LLM-independent).
        self.llm_report_fn = llm_report_fn

    def request_erasure(self, identifier: str) -> ErasureDecision:
        scan_result = pii_scanner.scan(identifier, include_names=True)

        if not scan_result.has_pii:
            return ErasureDecision(
                status="not_found",
                subject_id=None,
                chunks_removed=[],
                reason="Identifier did not match any recognized PII pattern (email/phone/ID/name). "
                       "Provide a more specific identifier.",
            )

        candidate_subjects = set()
        for fp in scan_result.fingerprints:
            sid = self.registry.find_subject_by_fingerprint(fp)
            if sid:
                candidate_subjects.add(sid)

        if len(candidate_subjects) == 0:
            return ErasureDecision(
                status="not_found",
                subject_id=None,
                chunks_removed=[],
                reason="No stored data is linked to this identifier. Nothing to erase.",
            )

        if len(candidate_subjects) > 1:
            return ErasureDecision(
                status="flagged_for_review",
                subject_id=None,
                chunks_removed=[],
                reason=f"Identifier resolves to {len(candidate_subjects)} distinct subject records "
                       f"(possible identifier collision). Escalated to human review rather than "
                       f"risking deletion of the wrong person's data.",
            )

        subject_id = candidate_subjects.pop()

        # low-confidence-only match guard: if every matching fingerprint came
        # from a fuzzy name match (confidence < 0.85) rather than a hard
        # identifier (email/phone/ID), require human confirmation.
        hard_id_types = {"EMAIL", "PHONE_FR", "PHONE_INTL", "IBAN", "FR_NIR", "PASSPORT_FR"}
        matched_types = {m.entity_type for m in scan_result.matches}
        if not (matched_types & hard_id_types):
            self.audit_log.record(
                action="erasure_flagged_for_review",
                subject_id=subject_id,
                details={"reason": "name-only low-confidence match", "matched_types": list(matched_types)},
            )
            return ErasureDecision(
                status="flagged_for_review",
                subject_id=subject_id,
                chunks_removed=[],
                reason="Only a name-based (low-confidence) match was found. Confirm with a hard "
                       "identifier (email, phone, national ID) before erasure, or approve manually.",
            )

        chunks_removed = self.vector_store.erase_subject(subject_id)
        self.registry.mark_erased(subject_id)

        entry = self.audit_log.record(
            action="erasure_executed",
            subject_id=subject_id,
            details={"chunks_removed": chunks_removed, "matched_types": list(matched_types)},
        )

        report_context = {
            "subject_id": subject_id,
            "chunks_removed": len(chunks_removed),
            "matched_identifier_types": list(matched_types),
            "audit_entry_hash": entry["entry_hash"],
            "timestamp": entry["timestamp"],
        }
        report = (
            self.llm_report_fn(report_context)
            if self.llm_report_fn
            else self._template_report(report_context)
        )

        return ErasureDecision(
            status="executed",
            subject_id=subject_id,
            chunks_removed=chunks_removed,
            reason="Unambiguous match on a hard identifier. Erasure executed.",
            report=report,
        )

    @staticmethod
    def _template_report(ctx: dict) -> str:
        return (
            f"GDPR Article 17 erasure request fulfilled for data subject {ctx['subject_id']}. "
            f"{ctx['chunks_removed']} vector embedding(s) and associated metadata were permanently "
            f"removed from the RAG index, matched via {', '.join(ctx['matched_identifier_types'])}. "
            f"Action logged at {ctx['timestamp']} with tamper-evident audit hash {ctx['audit_entry_hash'][:16]}...."
        )
