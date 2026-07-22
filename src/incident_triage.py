"""incident_triage — deterministic, privacy-preserving triage of synthetic support tickets.

Privacy contract (binding):
  1. Non-synthetic tickets (is_synthetic == False) are rejected with ValueError.
  2. Raw tickets / raw PII are never persisted and never logged.
  3. Logging is limited to {ticket_id, sha256(raw_payload), status}.
  4. Redaction is deterministic: identical input -> identical output.
  5. An ambiguous standalone numeric identifier forces status "uncertain".

Pure-Python, standard library only. Python 3.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from typing import Any, Dict, List, Optional, TypedDict, Union

__all__ = ["Ticket", "RedactionResult", "triage_ticket"]

logger = logging.getLogger("incident_triage")

# ---------------------------------------------------------------------------
# Data contract
# ---------------------------------------------------------------------------

JSONValue = Union[str, int, float, bool, None, Dict[str, Any], List[Any]]


class Ticket(TypedDict, total=False):
    """Input ticket."""

    ticket_id: str
    is_synthetic: bool
    payload: Dict[str, Any]


class RedactionResult(TypedDict, total=False):
    """Output of triage_ticket.

    status is one of: "redacted" | "uncertain".
    reason is present only when status == "uncertain".
    """

    ticket_id: str
    status: str  # "redacted" | "uncertain"
    redacted_payload: Dict[str, Any]
    reason: str


# ---------------------------------------------------------------------------
# Redaction rules (precedence: email, phone, account_id, PAN, CVV)
# ---------------------------------------------------------------------------

# Ordered so that later, greedier numeric rules cannot clobber structured PII.
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
# Phone requires a leading '+' so a bare 16-digit PAN is never mis-read as phone.
_PHONE_RE = re.compile(r"\+\d{10,15}\b")
# Account id token form, e.g. ACCT-000123 / ACC12345.
_ACCOUNT_RE = re.compile(r"\bAC(?:CT)?[-_]?\d{4,}\b", re.IGNORECASE)
_PAN_RE = re.compile(r"\b\d{12,19}\b")
_CVV_RE = re.compile(r"\b\d{3,4}\b")

# Key-name hints marking a field as "labeled" (so its value is not treated as an
# ambiguous standalone numeric identifier).
_LABEL_TOKENS = ("email", "phone", "account", "pan", "card", "cvv")

_STANDALONE_NUM_RE = re.compile(r"^\d{6,11}$")


def _key_is_labeled(key: str) -> bool:
    kl = key.lower()
    return any(tok in kl for tok in _LABEL_TOKENS)


def _redact_scalar_string(value: str, key: str) -> str:
    """Apply the ordered redaction rules to a single string value."""
    kl = key.lower()
    out = value

    # 1. email
    out = _EMAIL_RE.sub("<email>", out)
    # 2. phone
    out = _PHONE_RE.sub("<phone>", out)
    # 3. account_id (token form anywhere, or whole value when field is account-keyed)
    out = _ACCOUNT_RE.sub("<account_id>", out)
    if "account" in kl and out == value:
        # Field explicitly labeled as an account id but value not in token form.
        out = "<account_id>"
    # 4. PAN
    out = _PAN_RE.sub("<pan>", out)
    # 5. CVV — only when the field key marks it as a CVV.
    if "cvv" in kl:
        out = _CVV_RE.sub("<cvv>", out)

    return out


def _is_ambiguous_numeric(value: str, key: str) -> bool:
    """True when value is an unlabeled standalone 6-11 digit numeric identifier.

    PAN length (12-19) and CVV length (3-4) are excluded by the 6-11 bound.
    """
    if _key_is_labeled(key):
        return False
    return bool(_STANDALONE_NUM_RE.match(value.strip()))


class _RedactionState:
    __slots__ = ("uncertain", "reason")

    def __init__(self) -> None:
        self.uncertain = False
        self.reason: Optional[str] = None

    def flag_uncertain(self, reason: str) -> None:
        if not self.uncertain:
            self.uncertain = True
            self.reason = reason


def _redact_numeric(value: Union[int, float], key: str, state: _RedactionState) -> Any:
    """Redact JSON numeric leaves that represent labeled PII or a PAN."""
    kl = key.lower()
    if "account" in kl:
        return "<account_id>"
    if "cvv" in kl:
        return "<cvv>"
    if "pan" in kl or "card" in kl:
        return "<pan>"

    # Only integral numeric values can represent the digit-only identifiers
    # handled by the string rules. Preserve unrelated numbers and their types.
    if isinstance(value, float) and not value.is_integer():
        return value
    digits = str(int(value))
    if _PAN_RE.fullmatch(digits):
        return "<pan>"
    if _is_ambiguous_numeric(digits, key):
        state.flag_uncertain("ambiguous numeric identifier")
    return value


def _redact_value(value: Any, key: str, state: _RedactionState) -> Any:
    """Recursively redact PII leaves within nested payload structures."""
    if isinstance(value, dict):
        return {k: _redact_value(v, k, state) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_value(item, key, state) for item in value]
    if isinstance(value, str):
        if _is_ambiguous_numeric(value, key):
            state.flag_uncertain("ambiguous numeric identifier")
        return _redact_scalar_string(value, key)
    # bool must remain distinct because it is a subclass of int.
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, (int, float)):
        return _redact_numeric(value, key, state)
    return value


def _raw_sha256(payload: Dict[str, Any]) -> str:
    """Deterministic sha256 over the raw payload. Not persisted; digest only."""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def triage_ticket(ticket: Ticket) -> RedactionResult:
    """Redact a synthetic ticket and classify its status.

    Raises ValueError for non-synthetic tickets. Never persists raw data;
    logs only {ticket_id, sha256(raw_payload), status}.
    """
    if not ticket.get("is_synthetic", False):
        raise ValueError("Non-synthetic tickets are not allowed")

    ticket_id = ticket.get("ticket_id", "")
    payload: Dict[str, Any] = ticket.get("payload", {}) or {}

    # Compute digest before redaction (over raw), but keep only the digest.
    raw_digest = _raw_sha256(payload)

    state = _RedactionState()
    redacted_payload = _redact_value(payload, "", state)

    if state.uncertain:
        result: RedactionResult = {
            "ticket_id": ticket_id,
            "status": "uncertain",
            "redacted_payload": redacted_payload,
            "reason": state.reason or "ambiguous numeric identifier",
        }
    else:
        result = {
            "ticket_id": ticket_id,
            "status": "redacted",
            "redacted_payload": redacted_payload,
        }

    # Privacy-safe logging: id, digest of raw, status only. No raw payload/PII.
    logger.info(
        "triage",
        extra={
            "ticket_id": ticket_id,
            "sha256": raw_digest,
            "status": result["status"],
        },
    )

    return result
