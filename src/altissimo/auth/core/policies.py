"""Authorization policy checks.

Stateless helpers that raise `AuthForbiddenError` when a principal does
not satisfy the required authorization level.
"""

from __future__ import annotations

from typing import Any

from .exceptions import AuthForbiddenError, AuthUnauthorizedError
from .models import AuthReasonCode, FirebaseUser, GoogleUser


class AuthPolicyService:
    """Authorization policy checks."""

    @staticmethod
    def require_google_admin(user: GoogleUser) -> GoogleUser:
        """Require Google user to be admin."""
        if not user.admin:
            raise AuthForbiddenError("Forbidden", reason_code=AuthReasonCode.NOT_ADMIN)
        return user

    @staticmethod
    def require_firebase_admin(user: FirebaseUser) -> FirebaseUser:
        """Require Firebase user to have admin custom claim."""
        if not (user.custom_claims and user.custom_claims.get("admin")):
            raise AuthForbiddenError("Forbidden", reason_code=AuthReasonCode.NOT_ADMIN)
        return user

    @staticmethod
    def require_api_key_or_user(api_key_present: bool, user_present: bool) -> None:
        """Require either API key or authenticated user."""
        if not api_key_present and not user_present:
            raise AuthUnauthorizedError(
                "API Key or authenticated user required",
                reason_code=AuthReasonCode.MISSING_API_KEY,
            )

    @staticmethod
    def require_claim(user: FirebaseUser, claim: str, expected: Any = True) -> FirebaseUser:
        """Require Firebase user to have a specific custom claim value."""
        if not user.custom_claims or user.custom_claims.get(claim) != expected:
            raise AuthForbiddenError("Forbidden", reason_code=AuthReasonCode.INSUFFICIENT_CLAIMS)
        return user
