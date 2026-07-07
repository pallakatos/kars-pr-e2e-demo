"""Utilities for lightweight email address validation.

This module intentionally implements a small, predictable subset of email
validation rather than the full RFC 5322 grammar. It is meant for quick
sanity checks (form input, CLI arguments) where a clear, well-tested
heuristic is more useful than a permissive regex.
"""


def is_valid_email(address: str) -> bool:
    """Return ``True`` if ``address`` looks like a valid email address.

    The input is trimmed of surrounding whitespace first. An address is
    considered valid when **all** of the following hold:

    * it contains exactly one ``@`` separator;
    * the local part (before the ``@``) is non-empty;
    * the domain part (after the ``@``) contains at least one dot and does
      not start or end with a dot;
    * the trimmed address contains no whitespace characters.

    Args:
        address: The candidate email address. Non-``str`` values return
            ``False`` rather than raising.

    Returns:
        ``True`` if the address satisfies every rule above, else ``False``.

    Examples:
        >>> is_valid_email("  user@example.com  ")
        True
        >>> is_valid_email("no-at-sign.com")
        False
        >>> is_valid_email("user@localhost")
        False
    """
    if not isinstance(address, str):
        return False

    trimmed = address.strip()

    # Reject any internal whitespace (spaces, tabs, newlines) after trimming.
    if trimmed != address.strip() or any(ch.isspace() for ch in trimmed):
        return False

    # Require exactly one "@" separator.
    if trimmed.count("@") != 1:
        return False

    local, _, domain = trimmed.partition("@")

    # Local part must be non-empty.
    if not local:
        return False

    # Domain must be non-empty, contain a dot, and not start/end with a dot.
    if not domain:
        return False
    if "." not in domain:
        return False
    if domain.startswith(".") or domain.endswith("."):
        return False

    return True
