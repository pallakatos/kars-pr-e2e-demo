"""Incident triage module with privacy‑risk‑reducing redaction.

The implementation is deliberately lightweight and deterministic, suitable for
research and unit‑testing. It operates only on *synthetic* tickets – any
non‑synthetic input raises ``ValueError``.
"""

import re
import hashlib
import json
from typing import TypedDict, Literal, Any

# Regex patterns (compiled for performance)
_EMAIL_RE = re.compile(r"([a-zA-Z0-9_.+-]+)@([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)")
_PHONE_RE = re.compile(r"\+\d{1,3}[ -]?\d{1,14}")
_PAN_RE = re.compile(r"\b\d{12,19}\b")
_CVV_RE = re.compile(r"\b\d{3,4}\b")
_ACCOUNT_ID_RE = re.compile(r"\baccount[_-]?id[\s:=]*[a-zA-Z0-9_-]+\b", re.IGNORECASE)


class Ticket(TypedDict):
    id: str
    payload: dict
    is_synthetic: bool


class RedactionResult(TypedDict):
    ticket_id: str
    redacted_payload: dict
    status: Literal["redacted", "uncertain", "rejected"]
    reason: str | None


def _hash_payload(payload: Any) -> str:
    """Return a deterministic SHA‑256 hash of the JSON payload (sorted keys)."""
    txt = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(txt.encode()).hexdigest()


def _redact_value(value: Any) -> Any:
    """Recursively redact strings in dictionaries/lists.

    Returns a tuple ``(redacted_value, uncertain)`` where ``uncertain`` is a
    ``bool`` indicating whether any ambiguous numeric identifier was flagged.
    """
    if isinstance(value, str):
        original = value
        uncertain = False
        # Apply redaction patterns in order.
        value = _EMAIL_RE.sub(r"<email>", value)
        value = _PHONE_RE.sub(r"<phone>", value)
        value = _ACCOUNT_ID_RE.sub(r"<account_id>", value)
        # PAN replacement – avoid redacting short numbers that may be IDs.
        def pan_sub(m):
            return "<pan>"
        value = _PAN_RE.sub(pan_sub, value)
        # CVV: replace only when the surrounding key suggests a CVV.
        # Simple heuristic: if the string appears after "cvv" (case‑insensitive) in the same field.
        if re.search(r"cvv", original, re.IGNORECASE):
            value = _CVV_RE.sub(r"<cvv>", value)
        # Ambiguous numeric strings (e.g., 6‑digit) that are not captured above.
        if re.fullmatch(r"\d{4,8}", original) and not any(tag in original for tag in ["<pan>", "<cvv>"]):
            uncertain = True
        return value, uncertain
    elif isinstance(value, list):
        new_list = []
        any_uncertain = False
        for item in value:
            redacted, unc = _redact_value(item)
            new_list.append(redacted)
            any_uncertain = any_uncertain or unc
        return new_list, any_uncertain
    elif isinstance(value, dict):
        new_dict = {}
        any_uncertain = False
        for k, v in value.items():
            redacted, unc = _redact_value(v)
            new_dict[k] = redacted
            any_uncertain = any_uncertain or unc
        return new_dict, any_uncertain
    else:
        return value, False


def _apply_redaction(payload: dict) -> tuple[dict, bool]:
    """Redact the payload and return ``(redacted_payload, uncertain)``."""
    redacted, uncertain = _redact_value(payload)
    # ``redacted`` is guaranteed to be a dict because payload is a dict.
    return redacted, uncertain


def triage_ticket(ticket: Ticket) -> RedactionResult:
    """Process a ticket, enforce synthetic guard, redact PII, and classify.

    Parameters
    ----------
    ticket: Ticket
        The ticket to process.

    Returns
    -------
    RedactionResult
        Deterministic outcome.
    """
    if not ticket.get("is_synthetic", False):
        raise ValueError("Non‑synthetic tickets are not allowed")

    payload = ticket.get("payload", {})
    redacted_payload, uncertain = _apply_redaction(payload)

    status: Literal["redacted", "uncertain", "rejected"]
    reason: str | None = None

    if uncertain:
        status = "uncertain"
        reason = "ambiguous numeric identifier"
    else:
        status = "redacted"
        reason = None

    result: RedactionResult = {
        "ticket_id": ticket.get("id", "<unknown>"),
        "redacted_payload": redacted_payload,
        "status": status,
        "reason": reason,
    }
    # For telemetry (not persisted) we could log hash, but we keep it out of the result.
    # Example: print(json.dumps({"ticket_id": result["ticket_id"], "hash": _hash_payload(payload), "status": status}))
    return result

# Exportable helper for CLI
def process_stream(stream):
    """Read newline‑delimited JSON tickets from *stream* and write results to stdout."""
    import sys
    for line in stream:
        line = line.strip()
        if not line:
            continue
        ticket = json.loads(line)
        try:
            res = triage_ticket(ticket)  # type: ignore[arg-type]
        except Exception as e:
            res = {
                "ticket_id": ticket.get("id", "<unknown>"),
                "redacted_payload": {},
                "status": "rejected",
                "reason": str(e),
            }
        sys.stdout.write(json.dumps(res) + "\n")

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        with open(sys.argv[1], "r") as f:
            process_stream(f)
    else:
        process_stream(sys.stdin)
