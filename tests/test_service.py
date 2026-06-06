"""Tests for the AuthService orchestration layer."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from altissimo.auth.core.exceptions import AuthForbiddenError, AuthUnauthorizedError
from altissimo.auth.core.models import AuthReasonCode, FirebaseUser, GoogleUser
from altissimo.auth.service import AuthService

if TYPE_CHECKING:
    from tests.conftest import InMemoryKeyBackend


class TestAPIKeyMethods:
    def test_validate_api_key_success(self, api_key_backend: InMemoryKeyBackend) -> None:
        svc = AuthService(api_key_backend=api_key_backend)
        result = svc.validate_api_key(api_key_header="valid-key-1", api_key_query=None)
        assert result.id == "valid-key-1"

    def test_validate_api_key_missing(self, api_key_backend: InMemoryKeyBackend) -> None:
        svc = AuthService(api_key_backend=api_key_backend)
        with pytest.raises(AuthUnauthorizedError) as exc:
            svc.validate_api_key(api_key_header=None, api_key_query=None)
        assert exc.value.reason_code == AuthReasonCode.MISSING_API_KEY

    def test_validate_api_key_invalid(self, api_key_backend: InMemoryKeyBackend) -> None:
        svc = AuthService(api_key_backend=api_key_backend)
        with pytest.raises(AuthUnauthorizedError) as exc:
            svc.validate_api_key(api_key_header="nonexistent", api_key_query=None)
        assert exc.value.reason_code == AuthReasonCode.INVALID_API_KEY

    def test_validate_api_key_prefers_header(self, api_key_backend: InMemoryKeyBackend) -> None:
        svc = AuthService(api_key_backend=api_key_backend)
        result = svc.validate_api_key(api_key_header="valid-key-1", api_key_query="valid-key-2")
        assert result.id == "valid-key-1"

    def test_validate_api_key_optional_returns_none(self, api_key_backend: InMemoryKeyBackend) -> None:
        svc = AuthService(api_key_backend=api_key_backend)
        assert svc.validate_api_key_optional(api_key_header=None, api_key_query=None) is None

    def test_validate_api_key_optional_returns_key(self, api_key_backend: InMemoryKeyBackend) -> None:
        svc = AuthService(api_key_backend=api_key_backend)
        result = svc.validate_api_key_optional(api_key_header="valid-key-1", api_key_query=None)
        assert result is not None
        assert result.id == "valid-key-1"

    def test_no_backend_raises_runtime_error(self) -> None:
        svc = AuthService()
        with pytest.raises(RuntimeError, match="APIKeyBackend"):
            svc.get_api_key("any")


class TestFirebaseMethods:
    def test_validate_firebase_user(self, firebase_user: FirebaseUser) -> None:
        class FakeProvider:
            @staticmethod
            def verify_token(token: str) -> FirebaseUser:
                return firebase_user

        svc = AuthService(firebase_provider=FakeProvider())
        result = svc.validate_firebase_user("token")
        assert result.uid == firebase_user.uid

    def test_validate_firebase_admin_rejects_non_admin(self, firebase_user: FirebaseUser) -> None:
        class FakeProvider:
            @staticmethod
            def verify_token(token: str) -> FirebaseUser:
                return firebase_user

        svc = AuthService(firebase_provider=FakeProvider())
        with pytest.raises(AuthForbiddenError):
            svc.validate_firebase_admin("token")

    def test_validate_firebase_admin_accepts_admin(self, firebase_admin_user: FirebaseUser) -> None:
        class FakeProvider:
            @staticmethod
            def verify_token(token: str) -> FirebaseUser:
                return firebase_admin_user

        svc = AuthService(firebase_provider=FakeProvider())
        result = svc.validate_firebase_admin("token")
        assert result.uid == firebase_admin_user.uid


class TestGoogleMethods:
    def test_validate_google_user(self, google_user: GoogleUser) -> None:
        class FakeProvider:
            @staticmethod
            def get_user_from_token(token: str) -> GoogleUser:
                return google_user

        svc = AuthService(google_provider=FakeProvider())
        result = svc.validate_google_user("token")
        assert result.id == google_user.id

    def test_validate_google_admin_rejects_non_admin(self, google_user: GoogleUser) -> None:
        class FakeProvider:
            @staticmethod
            def get_user_from_token(token: str) -> GoogleUser:
                return google_user

        svc = AuthService(google_provider=FakeProvider())
        with pytest.raises(AuthForbiddenError):
            svc.validate_google_admin("token")


class TestIAPMethods:
    def test_get_iap_identity(self) -> None:
        svc = AuthService()
        identity = svc.get_iap_identity(
            {
                "X-Goog-Authenticated-User-Email": "accounts.google.com:user@test.com",
                "X-Goog-Authenticated-User-Id": "accounts.google.com:uid-1",
            }
        )
        assert identity.email == "user@test.com"
        assert identity.user_id == "uid-1"


class TestWebhookMethods:
    def test_no_provider_raises_runtime_error(self) -> None:
        svc = AuthService()
        with pytest.raises(RuntimeError, match="WebhookProvider"):
            svc.verify_webhook("payload", "sig")
