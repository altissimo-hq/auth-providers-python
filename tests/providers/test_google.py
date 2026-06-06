"""Tests for the Google OAuth2 auth provider."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from altissimo.auth.core.exceptions import AuthUnauthorizedError, GoogleTokenVerificationError
from altissimo.auth.core.models import AuthReasonCode
from altissimo.auth.providers.google import GoogleAuthProvider


def _token_payload(**overrides) -> dict:
    base = {
        "iss": "accounts.google.com",
        "azp": "client-id",
        "aud": "client-id",
        "sub": "google-uid-1",
        "email": "user@example.com",
        "email_verified": True,
        "iat": 1700000000,
        "exp": 1700003600,
    }
    base.update(overrides)
    return base


class TestVerifyGoogleIdToken:
    @patch("altissimo.auth.providers.google.id_token")
    @patch("altissimo.auth.providers.google.requests")
    def test_success(self, mock_requests: MagicMock, mock_id_token: MagicMock) -> None:
        mock_id_token.verify_oauth2_token.return_value = _token_payload()

        result = GoogleAuthProvider.verify_google_id_token("valid-token")

        assert result.sub == "google-uid-1"
        assert result.email == "user@example.com"

    @patch("altissimo.auth.providers.google.id_token")
    @patch("altissimo.auth.providers.google.requests")
    def test_malformed_raises(self, mock_requests: MagicMock, mock_id_token: MagicMock) -> None:
        from google.auth.exceptions import MalformedError

        mock_id_token.verify_oauth2_token.side_effect = MalformedError("bad")

        with pytest.raises(GoogleTokenVerificationError, match="Malformed"):
            GoogleAuthProvider.verify_google_id_token("bad-token")

    @patch("altissimo.auth.providers.google.id_token")
    @patch("altissimo.auth.providers.google.requests")
    def test_invalid_issuer_raises(self, mock_requests: MagicMock, mock_id_token: MagicMock) -> None:
        mock_id_token.verify_oauth2_token.return_value = _token_payload(iss="evil.com")

        with pytest.raises(ValueError, match="Invalid issuer"):
            GoogleAuthProvider.verify_google_id_token("bad-issuer-token")


class TestGetUserFromToken:
    @patch("altissimo.auth.providers.google.id_token")
    @patch("altissimo.auth.providers.google.requests")
    def test_success(self, mock_requests: MagicMock, mock_id_token: MagicMock) -> None:
        mock_id_token.verify_oauth2_token.return_value = _token_payload(hd="example.com")

        user = GoogleAuthProvider.get_user_from_token("valid-token")

        assert user.id == "google-uid-1"
        assert user.email == "user@example.com"
        assert user.hd == "example.com"
        assert user.admin is False

    @patch("altissimo.auth.providers.google.id_token")
    @patch("altissimo.auth.providers.google.requests")
    def test_invalid_token_raises_unauthorized(self, mock_requests: MagicMock, mock_id_token: MagicMock) -> None:
        from google.auth.exceptions import MalformedError

        mock_id_token.verify_oauth2_token.side_effect = MalformedError("bad")

        with pytest.raises(AuthUnauthorizedError) as exc:
            GoogleAuthProvider.get_user_from_token("bad-token")
        assert exc.value.reason_code == AuthReasonCode.INVALID_GOOGLE_TOKEN
