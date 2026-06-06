"""Altissimo Auth — reusable, framework-agnostic authentication library."""

from __future__ import annotations

from .core.exceptions import (
    AuthError,
    AuthForbiddenError,
    AuthNotFoundError,
    AuthUnauthorizedError,
    GoogleTokenVerificationError,
)
from .core.models import (
    AuthPrincipal,
    AuthReasonCode,
    AuthSource,
    GoogleTokenInfo,
    GoogleUser,
    IAPIdentity,
)

__all__ = [
    "AuthError",
    "AuthForbiddenError",
    "AuthNotFoundError",
    "AuthPrincipal",
    "AuthReasonCode",
    "AuthSource",
    "AuthUnauthorizedError",
    "GoogleTokenInfo",
    "GoogleTokenVerificationError",
    "GoogleUser",
    "IAPIdentity",
]
