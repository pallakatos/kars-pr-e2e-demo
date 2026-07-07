"""Tests for :func:`email_validator.is_valid_email`."""

import pytest

from email_validator import is_valid_email


def test_valid_address():
    """A well-formed address passes."""
    assert is_valid_email("user@example.com") is True


def test_valid_address_is_trimmed():
    """Surrounding whitespace is stripped before validation."""
    assert is_valid_email("  user@example.com  ") is True


def test_missing_at_sign():
    """An address without an '@' is rejected."""
    assert is_valid_email("user.example.com") is False


def test_multiple_at_signs():
    """More than one '@' is rejected."""
    assert is_valid_email("user@@example.com") is False
    assert is_valid_email("a@b@example.com") is False


def test_empty_local_part():
    """A missing local part is rejected."""
    assert is_valid_email("@example.com") is False


def test_domain_without_dot():
    """A domain with no dot is rejected."""
    assert is_valid_email("user@localhost") is False


def test_leading_dot_domain():
    """A domain that starts with a dot is rejected."""
    assert is_valid_email("user@.example.com") is False


def test_trailing_dot_domain():
    """A domain that ends with a dot is rejected."""
    assert is_valid_email("user@example.com.") is False


def test_internal_whitespace():
    """Whitespace inside the address is rejected."""
    assert is_valid_email("user name@example.com") is False
    assert is_valid_email("user@exa mple.com") is False


def test_empty_and_non_string():
    """Empty strings and non-str inputs are rejected, not raised."""
    assert is_valid_email("") is False
    assert is_valid_email("   ") is False
    assert is_valid_email(None) is False


@pytest.mark.parametrize(
    "address",
    [
        "first.last@sub.example.co.uk",
        "a@b.io",
        "kars-agent@users.noreply.github.com",
    ],
)
def test_various_valid_addresses(address):
    """A spread of realistic valid addresses all pass."""
    assert is_valid_email(address) is True
