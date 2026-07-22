# Privacy-risk-reducing triage for payment-outage support tickets

**Status:** implementation-ready research proposal (production code is out of scope)  
**Product:** Northstar Payments  
**Safety note:** all examples are synthetic. This proposal makes no compliance-certification claim.

## Evidence and repository fit

Research is pinned to `main` commit `6dc53d360a2f05bebcb9b8e61c4141f52c47b039` (commit message: `Add email validator + tests (#14)`). The repository is a small Python/pytest project: `src/email_validator.py` blob `8266efa4f8740945860220be0b837c7918f5564c` exposes one typed, documented pure function; `tests/test_email_validator.py` blob `35ebe55a0747a4c73945d50a9a553c4494fa7a6b` uses direct assertions and `pytest.mark.parametrize`; `conftest.py` blob `d2b707f1aad7c86417aa54e05b4dee2ac8d1a319` adds `src` to `sys.path`; `.gitignore` blob `75c61823b87164dde85ad0f2c78c300e011cc8a2` ignores Python/pytest caches. The proposed module and tests follow those conventions without changing existing production code in this research PR.

Managed Playwright retrieved the authoritative NIST page **Privacy Framework | NIST**, <https://www.nist.gov/privacy-framework>, at `2026-07-13T23:41:12Z`. The page describes the framework as a tool to improve individuals' privacy through enterprise risk management. Derived product requirement: ticket triage MUST treat disclosure of personal/payment data as an enterprise risk and provide explicit identify, control, measurement, and review points; this is design guidance, not a claim of NIST endorsement or certification.

## Users and outcome

* **Support agents** receive an actionable outage category and safe summary without unnecessary sensitive values.
* **Incident commanders** receive aggregate symptoms, impact, and routing signals without raw ticket text.
* **Privacy/security reviewers** receive deterministic reasons and a restricted manual-review queue for ambiguous or high-risk records.
* **Customers** benefit from less propagation of data they placed in tickets.

Outcome: reduce exposure during outage triage while preserving useful routing. Success means deterministic redaction before classification/logging, conservative manual review, measurable utility, and no raw-sensitive telemetry.

## Normative requirements

### Redaction

1. The boundary MUST accept text in memory and redact before persistence, classification, summarization, telemetry, or exception reporting.
2. It MUST replace email addresses, phone numbers, IPv4 addresses, access/bearer tokens, bank-account/IBAN-like values, and payment-card candidates with typed placeholders such as `[EMAIL_1]`.
3. A 13–19 digit card candidate MUST be replaced only after normalization and a Luhn check; the original and normalized digits MUST then be discarded. Non-Luhn long digit sequences MUST trigger manual review rather than be emitted unchanged.
4. IDs matching configured merchant/customer/transaction patterns MUST become keyed-HMAC aliases (`[TRANSACTION_<digest>]`) using a runtime secret; raw values and the key MUST never be returned. Aliases are stable only within the configured rotation period.
5. Overlapping matches MUST use precedence `token > payment-card > bank-account > configured-ID > email > phone > IP`; replacement MUST be left-to-right and deterministic.
6. Input MUST be bounded to 64 KiB UTF-8. Invalid UTF-8, oversize input, detector failure, or redaction uncertainty MUST fail closed to manual review with no partial output.
7. Returned `safe_summary` MUST be generated exclusively from redacted text and MUST be at most 500 characters. No API result may contain raw matches.

### Manual review

Manual review MUST be selected when: detector confidence is below configured threshold; an unknown 13–19 digit sequence appears; secrets/private keys are suspected; malformed/oversize input occurs; detectors fail; or an unsupported attachment/HTML body is present. Automatic routing MUST stop. The queue message MUST contain only ticket ID alias, reason codes, detector versions, and already-redacted excerpt (maximum 500 characters). Raw input access, if operationally necessary, belongs in the existing restricted source system and is never copied into this feature. Review decisions MUST use least-privilege access and be audited with actor alias, decision, reason, and timestamp—never ticket text.

### No sensitive logging

The library and CLI MUST NOT log, print to stderr, trace, metric-label, or exception-message raw ticket text, matched values, normalized values, HMAC keys, prompts, model responses, or redacted excerpts. CLI stdout is the documented result channel and contains only safe output. Logs MAY contain event name, aliased ticket ID, reason codes, detector/config version, durations, counts, and outcome. Exception messages MUST use fixed codes. Tests MUST install a capture handler and assert synthetic sentinel values are absent from stdout/stderr/logs/traces.

## Python API

Proposed `src/incident_triage.py`:

```python
from dataclasses import dataclass
from typing import Literal, Mapping, Sequence

@dataclass(frozen=True)
class TriageRequest:
    ticket_id: str
    text: str
    channel: Literal["email", "web", "chat"]
    metadata: Mapping[str, str]

@dataclass(frozen=True)
class TriageResult:
    ticket_id_alias: str
    disposition: Literal["auto_route", "manual_review"]
    category: Literal["payment_outage", "degraded", "unrelated", "unknown"]
    safe_summary: str | None
    redacted_text: str | None
    reason_codes: Sequence[str]
    detector_version: str

class TriageConfig: ...

def triage_ticket(request: TriageRequest, config: TriageConfig) -> TriageResult:
    """Deterministically redact, assess, then route; fail closed."""
```

`metadata` uses an allowlist (`service`, `region`, `channel`) and rejects other keys to manual review. Implementations MUST NOT mutate `request` or cache raw values.

## JSONL CLI

Command: `python -m incident_triage --config CONFIG.jsonl` reads one UTF-8 JSON object per stdin line and writes exactly one `TriageResult` JSON object per stdout line, preserving order. Schema fields map to `TriageRequest`; unknown fields, invalid JSON/types, blank/oversize lines, or processing errors produce a safe manual-review result with fixed reason code and aliased ID where possible. Exit `0` when all lines were processed (manual review is valid), `2` for startup/config failure, `3` for stream I/O failure. stderr contains fixed non-sensitive diagnostics only. No batching persists raw lines.

Synthetic input:
```json
{"ticket_id":"syn-17","text":"Payments fail; contact alex@example.test; test card 4242 4242 4242 4242","channel":"web","metadata":{"service":"checkout","region":"test-1"}}
```
Synthetic output (digest illustrative):
```json
{"ticket_id_alias":"t_8f1a","disposition":"auto_route","category":"payment_outage","safe_summary":"Payments fail; contact [EMAIL_1]; test card [PAYMENT_CARD_1]","redacted_text":"Payments fail; contact [EMAIL_1]; test card [PAYMENT_CARD_1]","reason_codes":[],"detector_version":"1.0"}
```

## Architecture and data flow

`JSONL adapter / Python caller -> size+encoding gate -> allowlist metadata -> deterministic detectors -> overlap resolver -> replacer/HMAC aliaser -> residual-risk gate -> rules-based outage classifier -> safe summarizer -> result`. A parallel **sanitized-only** path emits metrics and manual-review envelopes. Raw text remains request-scoped and is released after redaction. Detector/config versions are pinned in every result. Initial implementation is deterministic; no external model or network call is needed.

Trust boundaries are the caller-to-process boundary, runtime secret provider, restricted source ticket store, manual-review queue, and telemetry sink. The triage component receives no credentials to write raw tickets.

## Threat model

| Threat | Control | Residual risk |
|---|---|---|
| Customer pastes card/account/token | typed detectors, Luhn, token precedence, fail closed | novel formats; manual review |
| Crafted overlap bypass | deterministic precedence and adversarial tests | Unicode confusables; normalization tests/review |
| Sensitive logs/errors | sanitize first, fixed error codes, sentinel leakage tests | host crash dumps; disable/restrict dumps operationally |
| Linkability through aliases | keyed HMAC and rotation | within-window correlation is intentional and access-controlled |
| Prompt/model exfiltration | no model/network in v1 | future ML requires separate review |
| Malicious attachment/HTML | unsupported => manual review | reviewers remain exposed in source system |
| Classification error during outage | conservative threshold, shadow rollout, human override | delayed routing |
| Re-identification through telemetry | bounded dimensions, no free text, minimum cohort sizes | rare combinations; periodic review |

Abuse cases include delimiter injection into JSONL, catastrophic-regex inputs, Unicode digits, repeated secrets, and poisoned metadata. Use linear/bounded detectors, strict JSON decoding, an allowlist, time/size limits, and property tests.

## Alternatives

1. **Send raw tickets to an LLM:** rejected for v1 because it expands disclosure and nondeterminism.
2. **Regex-only redaction then always auto-route:** rejected because ambiguous numeric sequences and detector failures need fail-closed review.
3. **Manual review of every ticket:** strongest conservatism but unacceptable outage latency and reviewer exposure.
4. **Rely on upstream masking:** insufficient defense in depth and cannot prove sanitize-before-log locally.

## Telemetry and evaluation

Allowed counters/histograms: `triage_total{disposition,category,detector_version}`, `redaction_total{type}`, `manual_review_total{reason}`, processing latency, CLI parse failures, and override counts. Labels MUST be enum-bounded; no ticket IDs, aliases, text, excerpts, merchant/customer values, or free-form errors. Dashboards enforce minimum cohort display of 20 and retention per Northstar's approved operational policy (this proposal defines no compliance retention period).

Use a versioned, synthetic-only test corpus plus separately governed aggregate production metrics. Gates: synthetic sensitive-value recall 100% for enumerated formats; leakage tests 0 occurrences; p95 under 50 ms for 8 KiB locally benchmarked inputs; auto-route precision target >=95% in labeled synthetic evaluation; manual-review rate monitored, not optimized at privacy's expense.

## Rollout and rollback

1. Unit/property/fuzz tests on synthetic data; security and privacy design review.
2. Offline replay using synthetic corpus only.
3. Shadow mode on sanitized copies produced at ingress; no routing effects; compare aggregate outcomes.
4. 1% then 10% then 50% then 100% traffic, with on-call and daily privacy-risk review.
5. Stop/rollback to existing routing if any sentinel leakage, detector error >0.1%, p95 >100 ms, or auto-route precision below 95%. Kill switch forces all records to existing/manual flow. Config and alias-key rotation are independently reversible; never weaken redaction to restore availability.

## Engineering work packets (non-overlapping)

* **WP1 — Redaction core:** implement request/config/result types, bounded detectors, Luhn, overlap resolution, HMAC aliasing, residual-risk gate, and pure unit/property tests in `src/incident_triage.py` and `tests/test_incident_triage_redaction.py`. No CLI, telemetry, or deployment.
* **WP2 — Classification and safe summary:** implement deterministic outage taxonomy and summary operating only on WP1 redacted structures, with synthetic accuracy fixtures in separate classifier modules/tests. No detectors, CLI, or metrics exporter.
* **WP3 — JSONL adapter:** implement stdin/stdout schema, ordering, exit codes, safe fixed diagnostics, and subprocess tests. Consume public WP1/WP2 APIs; no core logic or telemetry backend.
* **WP4 — Operational integration:** implement bounded telemetry, sanitized manual-review envelope adapter, feature flags, dashboards/runbook, shadow/canary controls, and leakage/rollback integration tests. No modification of detector/classifier/CLI algorithms.

Dependencies: WP1 precedes WP2; WP3 can begin against frozen interfaces after WP1; WP4 consumes all stable outputs. Each packet is independently reviewable and has exclusive file ownership negotiated before delivery.

## Limitations

Formats outside the explicit detectors may be missed; synthetic evaluation cannot establish production accuracy; manual reviewers can still see source-system content under separate controls; HMAC aliases permit limited correlation; this proposal does not define legal retention, certify compliance, or implement production code. Attachments and HTML are deliberately unsupported in v1.
