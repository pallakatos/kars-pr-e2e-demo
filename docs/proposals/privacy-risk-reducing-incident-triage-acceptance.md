# Acceptance criteria: privacy-risk-reducing incident triage

All fixtures below are synthetic. Stable IDs are normative and map to executable pytest/subprocess expectations.

| ID | Acceptance criterion | Executable expectation |
|---|---|---|
| `NPT-PRIV-001` | Enumerated data is redacted before downstream use. | Parametrized pytest supplies synthetic email, phone, IPv4, bearer token, IBAN-like account, Luhn-valid card, and configured IDs; asserts typed placeholders appear and each sentinel is absent from every `TriageResult` field. |
| `NPT-PRIV-002` | Ambiguity and failures fail closed. | Tests inject non-Luhn 13–19 digit strings, invalid UTF-8 through CLI, 65537-byte text, unsupported HTML/attachment metadata, and detector exceptions; each yields `manual_review`, fixed reason code, and no partial/raw output. |
| `NPT-PRIV-003` | Overlap is deterministic. | Table tests assert precedence `token > payment-card > bank-account > configured-ID > email > phone > IP`, left-to-right numbering, and byte-for-byte repeatability across 100 runs. |
| `NPT-PRIV-004` | Aliasing is keyed and scoped. | Tests assert same ID/key/rotation gives same alias, different key/rotation changes it, aliases contain no raw substring, and key/raw value is absent from returned objects. |
| `NPT-PRIV-005` | Classification and summary consume redacted input only. | Spy/fake classifier and summarizer reject known sentinels; integration test proves calls occur only after redaction and summary length is <=500 characters. |
| `NPT-PRIV-006` | No sensitive logging. | `caplog`, captured stdout/stderr, fake tracer, and fake metrics exporter are searched for every synthetic sentinel after success and injected errors; zero matches required and metric label keys/values match an enum allowlist. |
| `NPT-PRIV-007` | JSONL contract is stable. | Subprocess test sends valid, malformed, blank, unknown-field, and multi-line records; asserts one ordered JSON result per input line, schema-valid safe output, exit 0 for processed review results, 2 for bad startup config, and 3 for injected I/O failure. |
| `NPT-PRIV-008` | Resource bounds resist abuse. | Tests enforce 64 KiB maximum, detector timeout/bounded behavior, and benchmark p95 <50 ms for a synthetic 8 KiB corpus; fuzz test includes Unicode digits and delimiter injection without crashes or leakage. |
| `NPT-PRIV-009` | Manual-review envelopes are minimal. | Schema test permits only aliased ticket ID, enum reasons, detector versions, and <=500-character already-redacted excerpt; attempts to add raw text or arbitrary metadata fail validation. |
| `NPT-PRIV-010` | Rollout controls fail safely. | Integration test toggles kill switch and threshold alarms; all new traffic returns to existing/manual flow, no redaction configuration is weakened, and an enum-only rollback event is emitted. |
| `NPT-PRIV-011` | Synthetic quality gates are met. | Evaluation command reports 100% recall on enumerated synthetic formats, 0 sentinel leakage, and >=95% auto-route precision on versioned synthetic outage fixtures. |
| `NPT-PRIV-012` | Existing behavior is unchanged. | `pytest -q` keeps all tests in `tests/test_email_validator.py` passing; research PR contains documentation/artifacts only and no production module modifications. |

Implementation delivery is accepted only when all IDs pass in CI and privacy/security reviewers approve the documented residual risks. Passing these criteria is not a compliance certification.
