"""triage_cli — stream JSONL tickets through triage_ticket, emit RedactionResult JSONL.

Usage:
    python -m bin.triage_cli samples.jsonl
    cat samples.jsonl | python -m bin.triage_cli

Reads one JSON ticket per line from the file argument (or stdin when no arg),
writes one RedactionResult JSON per line to stdout, and exits 0.
"""

from __future__ import annotations

import json
import os
import sys
from typing import IO, Iterator

# Allow `python bin/triage_cli.py` as well as `python -m bin.triage_cli`.
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_SRC_DIR = os.path.join(os.path.dirname(_THIS_DIR), "src")
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

from incident_triage import triage_ticket  # noqa: E402


def _iter_lines(stream: IO[str]) -> Iterator[str]:
    for line in stream:
        line = line.strip()
        if line:
            yield line


def _process(stream: IO[str], out: IO[str]) -> None:
    for line in _iter_lines(stream):
        ticket = json.loads(line)
        result = triage_ticket(ticket)
        out.write(json.dumps(result, sort_keys=True) + "\n")


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv:
        with open(argv[0], "r", encoding="utf-8") as fh:
            _process(fh, sys.stdout)
    else:
        _process(sys.stdin, sys.stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
