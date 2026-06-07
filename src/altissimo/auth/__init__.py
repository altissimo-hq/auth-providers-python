"""Altissimo Auth — reusable, framework-agnostic authentication library."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

from .core.exceptions import (
    AuthError,
    AuthForbiddenError,
    AuthNotFoundError,
    AuthUnauthorizedError,
    GoogleTokenVerificationError,
)
from .core.models import (
    APIKeyRecord,
    AuthReasonCode,
    AuthSource,
    FirebaseUser,
    GoogleTokenInfo,
    GoogleUser,
    IAPIdentity,
)

try:
    __version__ = version("altissimo-auth")
except PackageNotFoundError:
    __version__ = "0.1.0"

__all__ = [
    "APIKeyRecord",
    "AuthError",
    "AuthForbiddenError",
    "AuthNotFoundError",
    "AuthPrincipal",
    "AuthReasonCode",
    "AuthSource",
    "AuthUnauthorizedError",
    "FirebaseUser",
    "GoogleTokenInfo",
    "GoogleTokenVerificationError",
    "GoogleUser",
    "IAPIdentity",
    "__version__",
]
