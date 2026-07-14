# Incident Triage Proposal (Privacy‑Risk‑Reducing)

## Customer Outcome
- Faster resolution of payment‑related incidents while guaranteeing that personally identifiable information (PII) is never persisted in raw form.
- Users (customer‑support agents, fraud analysts) receive only redacted ticket data that is sufficient for triage decisions.

## Primary Users
- **Support agents** – need to understand the nature of the incident without seeing full card numbers, emails, or phone numbers.
- **Fraud analysts** – require redacted identifiers to correlate fraud patterns.
- **Compliance auditors** – review the deterministic redaction logic.

## Repository Fit
- The repo currently provides utility functions (`src/email_validator.py`).  Adding a **privacy‑aware incident‑triage** module fits the same lightweight, well‑tested utility style.
- No new external services are required; implementation lives entirely in Python.

## Synthetic‑Data‑Only Boundary
- All processing operates on **synthetic** ticket payloads for testing.  No production tickets are ingested during research.
- The API validates that any input marked `is_synthetic=True`; otherwise the request is rejected.

## Redaction Rules
| Data Type | Regex Pattern | Replacement |
|-----------|---------------|-------------|
| Email | `([a-zA-Z0-9_.+-]+)@([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)` | `<email>` |
| Phone (E.164) | `\+\d{1,3}[ -]?\d{1,14}` | `<phone>` |
| PAN (Primary Account Number) | `\b\d{12,19}\b` | `<pan>` |
| CVV | `\b\d{3,4}\b` (when preceded by `cvv` key) | `<cvv>` |
| Account ID | `\baccount[_-]?id[\s:=]*[a-zA-Z0-9_-]+\b` (case‑insensitive) | `<account_id>` |

- The redaction engine runs **deterministically** (same input → same output) to aid reproducible testing.
- If a pattern matches but confidence is low (e.g., ambiguous numeric strings), the field is flagged for **manual review**.

## Manual Review Path
- When the classifier returns `uncertain`, the system creates a **review ticket** containing the original data encrypted at rest (AES‑256) and accessible only to privileged auditors.
- Review tickets are stored for a maximum of 7 days and then securely deleted.

## No Raw‑Ticket Persistence or Sensitive Logging
- The pipeline never writes raw tickets to disk or logs.  All redacted payloads are the only artifacts persisted.
- Logging is limited to hash of the input (`sha256`) and redaction outcome (`redacted`, `uncertain`).

## Proposed Python API (src/incident_triage.py)
```python
from typing import TypedDict, Literal

class Ticket(TypedDict):
    id: str
    payload: dict  # arbitrary JSON from ticketing system
    is_synthetic: bool

class RedactionResult(TypedDict):
    ticket_id: str
    redacted_payload: dict
    status: Literal["redacted", "uncertain", "rejected"]
    reason: str | None

def triage_ticket(ticket: Ticket) -> RedactionResult:
    """Validate synthetic flag, apply deterministic redaction, and classify.

    Returns a deterministic result; raises `ValueError` for non‑synthetic data.
    """
    ...
```

## JSONL CLI (`bin/triage_cli.py`)
- Reads newline‑delimited JSON tickets from `stdin` or a file.
- Emits a JSONL stream of `RedactionResult` objects.
- Example usage:
```bash
cat synthetic_tickets.jsonl | python -m bin.triage_cli > redacted_results.jsonl
```

## Architecture Overview
```
[Ticket Source] -> (Synthetic Guard) -> [IncidentTriager]
                               |
                               v
                +----------------------------+
                | Deterministic Redactor    |
                +----------------------------+
                               |
                               v
               (Classification) -> (Review Queue) -> [Manual Review]
```
- Stateless pure‑Python library; no external DB.
- Optional plug‑in for message queue (Kafka) in production.

## Threat Model
| Threat | Mitigation |
|--------|------------|
| Ingestion of real PII | Synthetic guard rejects non‑synthetic tickets. |
| Regex over‑redaction (data loss) | Deterministic patterns with unit‑tests guarantee minimal false‑positives. |
| Insider exfiltration | No raw data persisted; review tickets encrypted and time‑boxed. |
| Side‑channel logging | Logging limited to hashes; no sensitive fields. |

## Telemetry (Privacy‑First)
- Emit only aggregate counters (`tickets_processed`, `redacted`, `uncertain`).
- Export via OpenTelemetry **metrics** endpoint; no user‑identifying tags.

## Rollout Plan
1. **Research** – prototype implementation and acceptance tests (this document). ✅
2. **Beta** – enable flag `enable_triage` for internal sandbox; ingest synthetic tickets only.
3. **Production** – gate behind `synthetic_guard=False` with additional audit.

## Work Packets (Non‑Overlapping)
| Packet | Owner | Deliverable |
|--------|-------|-------------|
| **PM** – Requirements & Acceptance | Product Manager | Detailed user stories, AC IDs, rollout checklist |
| **Privacy** – Redaction Logic & Review Flow | Privacy Engineer | Formal redaction spec, encryption key management, audit logs |
| **Backend** – Library & CLI | Backend Engineer | `src/incident_triage.py`, CLI, unit & integration tests |
| **QA** – Test Harness | QA Lead | Synthetic ticket generator, deterministic test suite, CI integration |

---
*All components are designed to be added without altering existing code paths.*
