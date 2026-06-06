"""Tests for core auth exceptions."""

from __future__ import annotations

from altissimo.auth.core.exceptions import (
    AuthError,
    AuthForbiddenError,
    AuthNotFoundError,
    AuthUnauthorizedError,
    GoogleTokenVerificationError,
)
from altissimo.auth.core.models import AuthReasonCode


class TestAuthError:
    def test_message_and_reason_code(self) -> None:
        err = AuthError("test", reason_code=AuthReasonCode.OK)
        assert str(err) == "test"
        assert err.reason_code == AuthReasonCode.OK


class TestAuthUnauthorizedError:
    def test_is_auth_error(self) -> None:
        err = AuthUnauthorizedError("bad token", reason_code=AuthReasonCode.INVALID_FIREBASE_TOKEN)
        assert isinstance(err, AuthError)
        assert err.reason_code == AuthReasonCode.INVALID_FIREBASE_TOKEN


class TestAuthForbiddenError:
    def test_is_auth_error(self) -> None:
        err = AuthForbiddenError("forbidden", reason_code=AuthReasonCode.NOT_ADMIN)
        assert isinstance(err, AuthError)


class TestAuthNotFoundError:
    def test_is_auth_error(self) -> None:
        err = AuthNotFoundError("not found", reason_code=AuthReasonCode.OK)
        assert isinstance(err, AuthError)


class TestGoogleTokenVerificationError:
    def test_is_not_auth_error(self) -> None:
        err = GoogleTokenVerificationError("malformed")
        assert not isinstance(err, AuthError)
        assert str(err) == "malformed"
