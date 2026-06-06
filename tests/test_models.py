"""Tests for core auth models."""

from __future__ import annotations

from altissimo.auth.core.models import (
    APIKeyRecord,
    AuthPrincipal,
    AuthReasonCode,
    AuthSource,
    FirebaseUser,
    GoogleUser,
    IAPIdentity,
)


class TestAuthSource:
    def test_values(self) -> None:
        assert AuthSource.API_KEY == "api_key"
        assert AuthSource.FIREBASE == "firebase"
        assert AuthSource.GOOGLE == "google"
        assert AuthSource.IAP == "iap"
        assert AuthSource.SERVICE_ACCOUNT == "service_account"
        assert AuthSource.WEBHOOK == "webhook"


class TestAuthReasonCode:
    def test_ok(self) -> None:
        assert AuthReasonCode.OK == "ok"

    def test_api_key_codes(self) -> None:
        assert AuthReasonCode.MISSING_API_KEY == "missing_api_key"
        assert AuthReasonCode.INVALID_API_KEY == "invalid_api_key"

    def test_firebase_codes(self) -> None:
        assert AuthReasonCode.INVALID_FIREBASE_TOKEN == "invalid_firebase_token"
        assert AuthReasonCode.EXPIRED_FIREBASE_TOKEN == "expired_firebase_token"
        assert AuthReasonCode.USER_DISABLED == "user_disabled"


class TestGoogleUser:
    def test_email_lowercased(self) -> None:
        user = GoogleUser(id="uid-1", email="User@Example.COM")
        assert user.email == "user@example.com"

    def test_admin_defaults_false(self) -> None:
        user = GoogleUser(id="uid-1", email="user@example.com")
        assert user.admin is False

    def test_extra_fields_allowed(self) -> None:
        user = GoogleUser(id="uid-1", email="user@example.com", custom_field="value")
        assert user.model_extra == {"custom_field": "value"}


class TestFirebaseUser:
    def test_basic_fields(self) -> None:
        user = FirebaseUser(uid="uid-1", email="user@test.com")
        assert user.uid == "uid-1"
        assert user.disabled is False
        assert user.custom_claims is None

    def test_extra_fields_allowed(self) -> None:
        user = FirebaseUser(uid="uid-1", extra_field="value")
        assert user.model_extra == {"extra_field": "value"}


class TestAPIKeyRecord:
    def test_basic(self) -> None:
        key = APIKeyRecord(id="key-1")
        assert key.id == "key-1"

    def test_extra_fields_allowed(self) -> None:
        key = APIKeyRecord(id="key-1", scopes=["read", "write"])
        assert key.model_extra == {"scopes": ["read", "write"]}


class TestIAPIdentity:
    def test_defaults(self) -> None:
        identity = IAPIdentity()
        assert identity.email is None
        assert identity.user_id is None


class TestAuthPrincipal:
    def test_creation(self) -> None:
        principal = AuthPrincipal(source=AuthSource.FIREBASE, subject="uid-1", email="user@test.com")
        assert principal.source == AuthSource.FIREBASE
        assert principal.admin is False
