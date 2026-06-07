"""Tests for core auth policies."""

from __future__ import annotations

import pytest

from altissimo.auth.core.exceptions import AuthForbiddenError, AuthUnauthorizedError
from altissimo.auth.core.models import AuthReasonCode, FirebaseUser, GoogleUser
from altissimo.auth.core.policies import AuthPolicyService


class TestRequireGoogleAdmin:
    def test_accepts_admin(self, google_admin: GoogleUser) -> None:
        result = AuthPolicyService.require_google_admin(google_admin)
        assert result is google_admin

    def test_rejects_non_admin(self, google_user: GoogleUser) -> None:
        with pytest.raises(AuthForbiddenError) as exc:
            AuthPolicyService.require_google_admin(google_user)
        assert exc.value.reason_code == AuthReasonCode.NOT_ADMIN


class TestRequireFirebaseAdmin:
    def test_accepts_admin(self, firebase_admin_user: FirebaseUser) -> None:
        result = AuthPolicyService.require_firebase_admin(firebase_admin_user)
        assert result is firebase_admin_user

    def test_rejects_non_admin(self, firebase_user: FirebaseUser) -> None:
        with pytest.raises(AuthForbiddenError) as exc:
            AuthPolicyService.require_firebase_admin(firebase_user)
        assert exc.value.reason_code == AuthReasonCode.NOT_ADMIN

    def test_rejects_no_claims(self) -> None:
        user = FirebaseUser(uid="uid", custom_claims=None)
        with pytest.raises(AuthForbiddenError):
            AuthPolicyService.require_firebase_admin(user)


class TestRequireApiKeyOrUser:
    def test_accepts_key_only(self) -> None:
        AuthPolicyService.require_api_key_or_user(api_key_present=True, user_present=False)

    def test_accepts_user_only(self) -> None:
        AuthPolicyService.require_api_key_or_user(api_key_present=False, user_present=True)

    def test_accepts_both(self) -> None:
        AuthPolicyService.require_api_key_or_user(api_key_present=True, user_present=True)

    def test_rejects_neither(self) -> None:
        with pytest.raises(AuthUnauthorizedError) as exc:
            AuthPolicyService.require_api_key_or_user(api_key_present=False, user_present=False)
        assert exc.value.reason_code == AuthReasonCode.MISSING_API_KEY


class TestRequireClaim:
    def test_accepts_matching_claim(self, firebase_admin_user: FirebaseUser) -> None:
        result = AuthPolicyService.require_claim(firebase_admin_user, "admin")
        assert result is firebase_admin_user

    def test_rejects_missing_claim(self, firebase_user: FirebaseUser) -> None:
        with pytest.raises(AuthForbiddenError) as exc:
            AuthPolicyService.require_claim(firebase_user, "admin")
        assert exc.value.reason_code == AuthReasonCode.INSUFFICIENT_CLAIMS

    def test_rejects_wrong_value(self) -> None:
        user = FirebaseUser(uid="uid", custom_claims={"role": "viewer"})
        with pytest.raises(AuthForbiddenError) as exc:
            AuthPolicyService.require_claim(user, "role", expected="admin")
        assert exc.value.reason_code == AuthReasonCode.INSUFFICIENT_CLAIMS
