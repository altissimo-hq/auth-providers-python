"""Auth exceptions.

All exceptions carry a machine-readable `reason_code` that adapters can use
for telemetry and structured error responses.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .models import AuthReasonCode


class AuthError(Exception):
    """Base auth exception."""

    def __init__(self, message: str, *, reason_code: AuthReasonCode) -> None:
        super().__init__(message)
        self.reason_code = reason_code


class AuthUnauthorizedError(AuthError):
    """Authentication failure (HTTP 401)."""


class AuthForbiddenError(AuthError):
    """Authorization failure (HTTP 403)."""


class AuthNotFoundError(AuthError):
    """Authenticated subject cannot be mapped (HTTP 404)."""


class GoogleTokenVerificationError(Exception):
    """Raised when Google OAuth2 token verification fails."""
