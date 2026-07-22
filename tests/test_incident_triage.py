"""Deterministic acceptance + boundary/negative suite for the incident-triage feature.

Stable test IDs map to acceptance criteria AC001-AC005 from
docs/proposals/incident-triage-acceptance.md, plus privacy-negative and
boundary cases required by the privacy review (conditions C1-C6).

The assertions are invariant-based (no raw PII may appear in output/logs;
markers must be present; reruns must be identical) rather than brittle string
matching, so they remain valid as long as the data contract holds:

    RedactionResult = {
        "ticket_id": str,
        "status": "redacted" | "uncertain",
        "redacted_payload": dict,
        "reason": str,        # present only when status == "uncertain"
    }
"""

from __future__ import annotations

import json
import logging
import subprocess
import sys
from pathlib import Path

import pytest

import incident_triage
from incident_triage import triage_ticket

REPO_ROOT = Path(__file__).resolve().parents[1]

RAW_EMAIL = "alice@example.com"
RAW_PHONE = "+15551234567"
RAW_PAN = "4111111111111111"
RAW_CVV = "123"


def _synthetic_ticket(**payload) -> dict:
    """Synthetic-ticket fixture factory (all tickets marked is_synthetic=True)."""
    return {
        "ticket_id": payload.pop("ticket_id", "T-TEST"),
        "is_synthetic": True,
        "payload": payload,
    }


def _flatten(obj) -> str:
    """Serialize any redacted result to a string for raw-leak assertions."""
    return json.dumps(obj, sort_keys=True)


# ---------------------------------------------------------------------------
# AC001 - triage_synthetic_guard
# ---------------------------------------------------------------------------

def test_ac001_triage_synthetic_guard():
    ticket = {"ticket_id": "T-NS", "is_synthetic": False, "payload": {"email": RAW_EMAIL}}
    with pytest.raises(ValueError) as exc:
        triage_ticket(ticket)
    assert str(exc.value) == "Non-synthetic tickets are not allowed"


def test_ac001_missing_flag_rejected():
    # Missing is_synthetic flag must also fail closed.
    with pytest.raises(ValueError):
        triage_ticket({"ticket_id": "T-NF", "payload": {"email": RAW_EMAIL}})


# ---------------------------------------------------------------------------
# AC002 - triage_deterministic
# ---------------------------------------------------------------------------

def test_ac002_triage_deterministic_redaction():
    ticket = _synthetic_ticket(
        ticket_id="T-002",
        email=RAW_EMAIL,
        phone=RAW_PHONE,
        card_pan=RAW_PAN,
        cvv=RAW_CVV,
    )
    result = triage_ticket(ticket)
    blob = _flatten(result["redacted_payload"])

    # Markers present.
    assert "<email>" in blob
    assert "<phone>" in blob
    assert "<pan>" in blob
    assert "<cvv>" in blob

    # No raw values leak.
    for raw in (RAW_EMAIL, RAW_PHONE, RAW_PAN, RAW_CVV):
        assert raw not in blob

    assert result["status"] == "redacted"


def test_ac002_deterministic_rerun_identical():
    ticket = _synthetic_ticket(
        ticket_id="T-002",
        email=RAW_EMAIL,
        phone=RAW_PHONE,
        card_pan=RAW_PAN,
        cvv=RAW_CVV,
    )
    first = triage_ticket(ticket)
    # C6: identical input -> identical output across repeated runs.
    for _ in range(5):
        assert triage_ticket(ticket) == first


# ---------------------------------------------------------------------------
# AC003 - triage_uncertain
# ---------------------------------------------------------------------------

def test_ac003_triage_uncertain_ambiguous_numeric():
    ticket = _synthetic_ticket(ticket_id="T-003", reference="123456")
    result = triage_ticket(ticket)
    assert result["status"] == "uncertain"
    assert "ambiguous numeric identifier" in result["reason"]


# ---------------------------------------------------------------------------
# AC004 - triage_logging (no sensitive logging)
# ---------------------------------------------------------------------------

def test_ac004_logging_no_raw_pii(caplog):
    ticket = _synthetic_ticket(
        ticket_id="T-LOG",
        email=RAW_EMAIL,
        card_pan=RAW_PAN,
    )
    with caplog.at_level(logging.INFO, logger="incident_triage"):
        triage_ticket(ticket)

    assert caplog.records, "expected at least one log record"
    rec = caplog.records[-1]

    # Permitted fields only.
    assert rec.ticket_id == "T-LOG"
    assert rec.status in ("redacted", "uncertain")
    assert len(rec.sha256) == 64 and all(c in "0123456789abcdef" for c in rec.sha256)

    # No raw PII anywhere in the emitted log text.
    full = caplog.text
    assert RAW_EMAIL not in full
    assert RAW_PAN not in full


# ---------------------------------------------------------------------------
# AC005 - triage_cli (end-to-end)
# ---------------------------------------------------------------------------

def test_ac005_triage_cli_end_to_end(tmp_path):
    tickets = [
        _synthetic_ticket(ticket_id="C-1", email=RAW_EMAIL, phone=RAW_PHONE),
        _synthetic_ticket(ticket_id="C-2", card_pan=RAW_PAN, cvv=RAW_CVV),
        _synthetic_ticket(ticket_id="C-3", reference="123456"),
    ]
    samples = tmp_path / "samples.jsonl"
    samples.write_text("\n".join(json.dumps(t) for t in tickets) + "\n", encoding="utf-8")

    proc = subprocess.run(
        [sys.executable, "-m", "bin.triage_cli", str(samples)],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr

    lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
    assert len(lines) == 3

    for ln in lines:
        obj = json.loads(ln)
        assert set(["ticket_id", "status", "redacted_payload"]).issubset(obj.keys())
        assert obj["status"] in ("redacted", "uncertain")
        assert isinstance(obj["redacted_payload"], dict)

    # No raw PII in CLI stdout.
    assert RAW_EMAIL not in proc.stdout
    assert RAW_PAN not in proc.stdout


# ---------------------------------------------------------------------------
# Boundary / negative (privacy conditions C1-C5)
# ---------------------------------------------------------------------------

def test_boundary_empty_payload():
    result = triage_ticket(_synthetic_ticket(ticket_id="T-EMPTY"))
    assert result["status"] == "redacted"
    assert result["redacted_payload"] == {}


def test_boundary_nested_payload_redacted():
    ticket = _synthetic_ticket(
        ticket_id="T-NEST",
        customer={"email": RAW_EMAIL, "contacts": [{"phone": RAW_PHONE}]},
    )
    result = triage_ticket(ticket)
    blob = _flatten(result["redacted_payload"])
    assert RAW_EMAIL not in blob
    assert RAW_PHONE not in blob
    assert "<email>" in blob and "<phone>" in blob


def test_boundary_cvv_key_beats_ambiguous():
    # C1: 3-4 digit value under cvv key -> <cvv>, never ambiguous.
    result = triage_ticket(_synthetic_ticket(ticket_id="T-CVV", cvv="1234"))
    assert result["status"] == "redacted"
    assert "<cvv>" in _flatten(result["redacted_payload"])


def test_boundary_pan_length_edges():
    # 12- and 19-digit numerics are PAN even in unlabeled fields (not ambiguous).
    for pan in ("123456789012", "1234567890123456789"):
        result = triage_ticket(_synthetic_ticket(ticket_id="T-PAN", note=pan))
        assert result["status"] == "redacted"
        assert pan not in _flatten(result["redacted_payload"])


def test_numeric_pii_fields_are_redacted():
    result = triage_ticket(
        _synthetic_ticket(
            ticket_id="T-NUMERIC",
            card_pan=4111111111111111,
            cvv=123,
            account_id=987654321,
        )
    )
    assert result["status"] == "redacted"
    assert result["redacted_payload"] == {
        "card_pan": "<pan>",
        "cvv": "<cvv>",
        "account_id": "<account_id>",
    }


def test_numeric_pii_nested_lists_and_float_forms_are_redacted():
    result = triage_ticket(
        _synthetic_ticket(
            ticket_id="T-NUMERIC-NESTED",
            customer={
                "cards": [4111111111111111, 5555555555554444.0],
                "credentials": [{"cvv": 123.0}, {"account_ids": [123456, 654321.0]}],
            },
            values=[4111111111111111],
        )
    )
    payload = result["redacted_payload"]
    assert payload["customer"]["cards"] == ["<pan>", "<pan>"]
    assert payload["customer"]["credentials"] == [
        {"cvv": "<cvv>"},
        {"account_ids": ["<account_id>", "<account_id>"]},
    ]
    assert payload["values"] == ["<pan>"]
