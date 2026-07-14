# Acceptance Criteria for Incident Triage Feature

## AC001 – Synthetic Guard Enforcement
- **Given** a ticket where `is_synthetic` is `false`
- **When** `triage_ticket` is called
- **Then** the function raises `ValueError` with message `"Non‑synthetic tickets are not allowed"`.

## AC002 – Deterministic Redaction
- **Given** a ticket containing an email `alice@example.com`, phone `+15551234567`, PAN `4111111111111111`, and CVV `123`
- **When** `triage_ticket` processes the ticket
- **Then** the returned `redacted_payload` contains `<email>`, `<phone>`, `<pan>`, `<cvv>` respectively, and no raw values appear.
- **And** repeated calls with the same input produce identical output.

## AC003 – Uncertain Classification
- **Given** a numeric string `"123456"` in a field not clearly identified as PAN or CVV
- **When** the redactor processes the field
- **Then** the result `status` is `"uncertain"` and `reason` includes `"ambiguous numeric identifier"`.

## AC004 – No Sensitive Logging
- **Given** any ticket processed
- **When** the library logs information
- **Then** logs contain only `ticket_id`, SHA‑256 hash of the raw payload, and a redaction `status` field; no raw PII appears.

## AC005 – CLI End‑to‑End Behaviour
- **Given** a JSONL file `samples.jsonl` with 3 synthetic tickets
- **When** the CLI `python -m bin.triage_cli samples.jsonl` runs
- **Then** it outputs 3 JSON lines each conforming to the `RedactionResult` schema and exits with status code `0`.

## Stable IDs for Test Harness
- `AC001` – `triage_synthetic_guard`
- `AC002` – `triage_deterministic`
- `AC003` – `triage_uncertain`
- `AC004` – `triage_logging`
- `AC005` – `triage_cli`

---
All tests are deterministic and can be run against the repository's CI pipeline.
