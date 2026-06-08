"""Tests for the Firebase auth provider."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from altissimo.auth.core.exceptions import AuthForbiddenError, AuthUnauthorizedError
from altissimo.auth.core.models import AuthReasonCode
from altissimo.auth.providers.firebase import FirebaseAuthProvider


def _mock_user_record(
    *,
    uid: str = "uid-1",
    disabled: bool = False,
    admin: bool = False,
    tokens_valid_after_timestamp: int | str | None = None,
) -> MagicMock:
    """Create a mock firebase_admin UserRecord."""
    record = MagicMock()
    record.uid = uid
    record.email = "user@example.com"
    record.email_verified = True
    record.disabled = disabled
    record.display_name = "Test User"
    record.phone_number = None
    record.photo_url = None
    record.provider_id = "firebase"
    record.tenant_id = None
    record.tokens_valid_after_timestamp = tokens_valid_after_timestamp
    record.custom_claims = {"admin": True} if admin else {}
    record.provider_data = []
    return record


class TestFirebaseAuthProvider:
    @patch("altissimo.auth.providers.firebase.firebase_auth")
    def test_verify_token_success(self, mock_auth: MagicMock) -> None:
        mock_auth.verify_id_token.return_value = {"uid": "uid-1"}
        mock_auth.get_user.return_value = _mock_user_record()

        user = FirebaseAuthProvider.verify_token("valid-token")

        assert user.uid == "uid-1"
        assert user.disabled is False
        mock_auth.verify_id_token.assert_called_once_with("valid-token")
        mock_auth.get_user.assert_called_once_with("uid-1")

    @patch("altissimo.auth.providers.firebase.firebase_auth")
    def test_verify_token_expired(self, mock_auth: MagicMock) -> None:
        from firebase_admin.auth import ExpiredIdTokenError

        mock_auth.verify_id_token.side_effect = ExpiredIdTokenError("expired", cause="test")

        with pytest.raises(AuthUnauthorizedError) as exc:
            FirebaseAuthProvider.verify_token("expired-token")
        assert exc.value.reason_code == AuthReasonCode.EXPIRED_FIREBASE_TOKEN

    @patch("altissimo.auth.providers.firebase.firebase_auth")
    def test_verify_token_invalid(self, mock_auth: MagicMock) -> None:
        from firebase_admin.auth import InvalidIdTokenError

        mock_auth.verify_id_token.side_effect = InvalidIdTokenError("invalid")

        with pytest.raises(AuthUnauthorizedError) as exc:
            FirebaseAuthProvider.verify_token("invalid-token")
        assert exc.value.reason_code == AuthReasonCode.INVALID_FIREBASE_TOKEN

    @patch("altissimo.auth.providers.firebase.firebase_auth")
    def test_verify_token_disabled_user(self, mock_auth: MagicMock) -> None:
        mock_auth.verify_id_token.return_value = {"uid": "uid-disabled"}
        mock_auth.get_user.return_value = _mock_user_record(uid="uid-disabled", disabled=True)

        with pytest.raises(AuthForbiddenError) as exc:
            FirebaseAuthProvider.verify_token("token-for-disabled")
        assert exc.value.reason_code == AuthReasonCode.USER_DISABLED

    @patch("altissimo.auth.providers.firebase.firebase_auth")
    def test_verify_token_with_timestamp_int(self, mock_auth: MagicMock) -> None:
        mock_auth.verify_id_token.return_value = {"uid": "uid-1"}
        mock_auth.get_user.return_value = _mock_user_record(tokens_valid_after_timestamp=1780928613000)

        user = FirebaseAuthProvider.verify_token("valid-token")

        assert user.uid == "uid-1"
        assert user.tokens_valid_after_timestamp == 1780928613000
