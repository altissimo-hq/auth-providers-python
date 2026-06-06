"""Tests for the IAP provider."""

from __future__ import annotations

from altissimo.auth.providers.iap import IAPProvider


class TestParseHeaderValue:
    def test_strips_google_prefix(self) -> None:
        assert IAPProvider.parse_header_value("accounts.google.com:User@Example.com") == "user@example.com"

    def test_handles_no_prefix(self) -> None:
        assert IAPProvider.parse_header_value("user@example.com") == "user@example.com"

    def test_handles_empty(self) -> None:
        assert IAPProvider.parse_header_value("") == ""

    def test_strips_whitespace(self) -> None:
        assert IAPProvider.parse_header_value("  user@example.com  ") == "user@example.com"


class TestGetIdentity:
    def test_extracts_from_headers(self) -> None:
        identity = IAPProvider.get_identity(
            {
                "X-Goog-Authenticated-User-Email": "accounts.google.com:User@Example.com",
                "X-Goog-Authenticated-User-Id": "accounts.google.com:USER-123",
            }
        )
        assert identity.email == "user@example.com"
        assert identity.user_id == "user-123"

    def test_missing_headers(self) -> None:
        identity = IAPProvider.get_identity({})
        assert identity.email is None
        assert identity.user_id is None

    def test_empty_header_values(self) -> None:
        identity = IAPProvider.get_identity(
            {
                "X-Goog-Authenticated-User-Email": "",
                "X-Goog-Authenticated-User-Id": "",
            }
        )
        assert identity.email is None
        assert identity.user_id is None
