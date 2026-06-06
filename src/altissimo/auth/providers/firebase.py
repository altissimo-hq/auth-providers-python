"""Firebase authentication provider.

Verifies Firebase ID tokens and resolves full user records via
``firebase_admin``.  The ``firebase-admin`` package is an optional
dependency — import this module only when the ``[firebase]`` extra
is installed.
"""

from __future__ import annotations

from typing import Any

from firebase_admin import auth as firebase_auth
from firebase_admin.auth import (
    ExpiredIdTokenError,
    InvalidIdTokenError,
    RevokedIdTokenError,
)

from ..core.exceptions import AuthForbiddenError, AuthUnauthorizedError
from ..core.models import AuthReasonCode, FirebaseUser


def _to_firebase_user(user_record: Any) -> FirebaseUser:
    """Map a ``firebase_admin.auth.UserRecord`` to our Pydantic model."""
    provider_data = [
        {
            "display_name": p.display_name,
            "email": p.email,
            "photo_url": p.photo_url,
            "provider_id": p.provider_id,
            "uid": p.uid,
        }
        for p in (user_record.provider_data or [])
    ]
    return FirebaseUser(
        uid=user_record.uid,
        email=user_record.email,
        email_verified=user_record.email_verified,
        disabled=user_record.disabled,
        display_name=user_record.display_name,
        phone_number=user_record.phone_number,
        photo_url=user_record.photo_url,
        provider_id=user_record.provider_id,
        tenant_id=user_record.tenant_id,
        tokens_valid_after_timestamp=user_record.tokens_valid_after_timestamp,
        custom_claims=user_record.custom_claims,
        provider_data=provider_data,
    )


class FirebaseAuthProvider:
    """Firebase-backed auth provider."""

    @staticmethod
    def verify_token(bearer_token: str) -> FirebaseUser:
        """Verify a Firebase ID token and return the resolved user.

        Raises:
            AuthUnauthorizedError: Token is invalid or expired.
            AuthForbiddenError: User account is disabled.
        """

        try:
            decoded = firebase_auth.verify_id_token(bearer_token)
        except ExpiredIdTokenError as exc:
            raise AuthUnauthorizedError(str(exc), reason_code=AuthReasonCode.EXPIRED_FIREBASE_TOKEN) from exc
        except (InvalidIdTokenError, RevokedIdTokenError, ValueError) as exc:
            raise AuthUnauthorizedError(str(exc), reason_code=AuthReasonCode.INVALID_FIREBASE_TOKEN) from exc

        uid = decoded["uid"]
        try:
            user_record = firebase_auth.get_user(uid)
        except Exception as exc:
            raise AuthUnauthorizedError(
                f"Failed to resolve Firebase user: {exc}",
                reason_code=AuthReasonCode.INVALID_FIREBASE_TOKEN,
            ) from exc

        user = _to_firebase_user(user_record)

        if user.disabled:
            raise AuthForbiddenError("User disabled", reason_code=AuthReasonCode.USER_DISABLED)

        return user
