"""Test stubs and helpers for altissimo-auth consumers.

This module provides lightweight stub auth classes and a ``sys.modules``
wiring helper so that consuming projects can test their Django Ninja
applications **without** importing the real ``ninja`` or ``django``
packages at conftest load time.

Usage in ``conftest.py``::

    from altissimo.auth.testing import install_test_modules, StubApiKeyAuth

    class MyApiKeyAuth(StubApiKeyAuth):
        def authenticate(self, request, key):
            api_key_id = key or request.GET.get("api_key")
            if not api_key_id:
                return None
            return MyBackend().get_key(api_key_id)

    install_test_modules(api_key_auth_class=MyApiKeyAuth)

    # Now configure Django and import your app normally...

.. note::

    This module deliberately avoids importing ``ninja``, ``django``,
    ``fastapi``, or any other framework package.  Only
    ``altissimo.auth.core`` (which is pure Python + Pydantic) is used.
"""

from __future__ import annotations

import sys
import types
from typing import Any

# Re-export core models and exceptions so consumers don't need separate imports.
from .core.exceptions import (
    AuthError,
    AuthForbiddenError,
    AuthNotFoundError,
    AuthUnauthorizedError,
)
from .core.models import (
    APIKeyRecord,
    AuthReasonCode,
    AuthSource,
    FirebaseUser,
    GoogleUser,
    IAPIdentity,
)

__all__ = [
    "APIKeyRecord",
    "AuthError",
    "AuthForbiddenError",
    "AuthNotFoundError",
    "AuthReasonCode",
    "AuthSource",
    "AuthUnauthorizedError",
    "FirebaseUser",
    "GoogleUser",
    "IAPIdentity",
    "StubApiKeyAuth",
    "StubFirebaseAuth",
    "StubGoogleAuth",
    "StubJWTAuth",
    "StubLayeredAuth",
    "install_test_modules",
]


# ---------------------------------------------------------------------------
# Stub auth classes
# ---------------------------------------------------------------------------


class StubApiKeyAuth:
    """API key auth stub for tests.

    Consumers should subclass and override :meth:`authenticate` to call
    their own backend.  The default implementation raises
    :class:`NotImplementedError`.

    The ``__call__`` method mirrors Django Ninja's ``APIKeyHeader`` behaviour:
    extract the key from the ``X-API-Key`` header (or ``api_key`` query param),
    then delegate to :meth:`authenticate`.
    """

    param_name: str = "X-API-Key"
    openapi_type: str = "apiKey"

    def __init__(self) -> None:
        self.openapi_security_schema = {
            "type": "apiKey",
            "in": "header",
            "name": self.param_name,
        }
        self.is_async = False

    def authenticate(self, request: Any, key: str | None) -> Any | None:
        """Override this in your conftest subclass."""
        raise NotImplementedError(
            "StubApiKeyAuth.authenticate() must be overridden. "
            "Subclass StubApiKeyAuth in your conftest and implement authenticate()."
        )

    def __call__(self, request: Any) -> Any | None:
        """Extract API key and delegate to :meth:`authenticate`."""
        key = None
        # Try header first (case-insensitive via headers dict if available)
        if hasattr(request, "headers"):
            key = request.headers.get(self.param_name) or request.headers.get(self.param_name.lower())
        # Fall back to META
        if not key and hasattr(request, "META"):
            meta_key = f"HTTP_{self.param_name.upper().replace('-', '_')}"
            key = request.META.get(meta_key)
        # Fall back to query param
        if not key and hasattr(request, "GET"):
            key = request.GET.get("api_key")
        return self.authenticate(request, key)


class StubFirebaseAuth:
    """Always-deny Firebase auth stub for tests.

    Returns ``None`` from both ``authenticate`` and ``__call__``,
    meaning requests using this auth will be denied (401) unless
    the test patches ``authenticate`` to return a :class:`FirebaseUser`.
    """

    openapi_type: str = "http"
    openapi_scheme: str = "bearer"

    def __init__(self) -> None:
        self.openapi_security_schema = {"type": "http", "scheme": "bearer"}
        self.is_async = False

    def authenticate(self, request: Any, token: str) -> Any | None:
        """Return ``None`` (deny).  Patch or override in tests."""
        return None

    def __call__(self, request: Any) -> Any | None:
        """Return ``None`` (deny)."""
        return None


class StubGoogleAuth:
    """Always-deny Google OAuth2 auth stub for tests."""

    openapi_type: str = "http"
    openapi_scheme: str = "bearer"

    def __init__(self) -> None:
        self.openapi_security_schema = {"type": "http", "scheme": "bearer"}
        self.is_async = False

    def authenticate(self, request: Any, token: str) -> Any | None:
        """Return ``None`` (deny).  Patch or override in tests."""
        return None

    def __call__(self, request: Any) -> Any | None:
        """Return ``None`` (deny)."""
        return None


class StubJWTAuth:
    """Always-deny JWT auth stub for tests."""

    openapi_type: str = "http"
    openapi_scheme: str = "bearer"

    def __init__(self, **kwargs: Any) -> None:
        self.openapi_security_schema = {"type": "http", "scheme": "bearer"}
        self.is_async = False
        # Accept and ignore config/kwargs to match JWTAuth(config=...) signature

    def authenticate(self, request: Any, token: str) -> Any | None:
        """Return ``None`` (deny).  Patch or override in tests."""
        return None

    def __call__(self, request: Any) -> Any | None:
        """Return ``None`` (deny)."""
        return None


class StubLayeredAuth:
    """Test-compatible LayeredAuth with the same gate + identity contract.

    Mirrors the real ``LayeredAuth`` behavior:

    1. Call ``gate(request)`` — if ``None``, return ``None`` (401).
    2. Stash gate result on ``request.gate_auth``.
    3. Check for ``Authorization: Bearer`` header:
       - Present → delegate to ``identity.authenticate(request, token)``.
       - Absent → set ``request.auth = None``, return truthy sentinel.
    """

    _ANONYMOUS = object()

    def __init__(self, gate: Any, identity: Any) -> None:
        self._gate = gate
        self._identity = identity
        if hasattr(gate, "openapi_security_schema"):
            self.openapi_security_schema = gate.openapi_security_schema

    def __call__(self, request: Any) -> Any | None:
        """Run layered authentication (mirrors real LayeredAuth)."""
        gate_result = self._gate(request)
        if gate_result is None:
            return None

        request.gate_auth = gate_result

        # Try headers dict first (case-insensitive), then META
        auth_header = ""
        if hasattr(request, "headers"):
            auth_header = request.headers.get("Authorization", "")
        elif hasattr(request, "META"):
            auth_header = request.META.get("HTTP_AUTHORIZATION", "")

        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
            if not token:
                request.auth = None
                return self._ANONYMOUS
            result = self._identity.authenticate(request, token)
            if result is None:
                return None
            return result

        request.auth = None
        return self._ANONYMOUS


# ---------------------------------------------------------------------------
# sys.modules installer
# ---------------------------------------------------------------------------


def install_test_modules(
    *,
    api_key_auth_class: type | None = None,
    firebase_auth_class: type | None = None,
    google_auth_class: type | None = None,
    jwt_auth_class: type | None = None,
    layered_auth_class: type | None = None,
) -> dict[str, types.ModuleType]:
    """Wire test stubs into ``sys.modules`` for the altissimo auth namespace.

    Call this **before** Django is configured (at the top of ``conftest.py``)
    to prevent import-time failures from ``ninja.security`` requiring Django
    settings.

    Args:
        api_key_auth_class: Custom ``ApiKeyAuth`` replacement.  Defaults to
            :class:`StubApiKeyAuth`.
        firebase_auth_class: Custom ``FirebaseAuth`` replacement.  Defaults to
            :class:`StubFirebaseAuth`.
        google_auth_class: Custom ``GoogleAuth`` replacement.  Defaults to
            :class:`StubGoogleAuth`.
        jwt_auth_class: Custom ``JWTAuth`` replacement.  Defaults to
            :class:`StubJWTAuth`.
        layered_auth_class: Custom ``LayeredAuth`` replacement.  Defaults to
            :class:`StubLayeredAuth`.

    Returns:
        A dict of module-name → module for all installed modules.

    Example::

        # conftest.py
        from altissimo.auth.testing import install_test_modules, StubApiKeyAuth

        class MyApiKeyAuth(StubApiKeyAuth):
            def authenticate(self, request, key):
                if not key:
                    return None
                return MyBackend().get_key(key)

        install_test_modules(api_key_auth_class=MyApiKeyAuth)

        # Now safe to configure Django and import your app code.
    """
    api_key_cls = api_key_auth_class or StubApiKeyAuth
    firebase_cls = firebase_auth_class or StubFirebaseAuth
    google_cls = google_auth_class or StubGoogleAuth
    jwt_cls = jwt_auth_class or StubJWTAuth
    layered_cls = layered_auth_class or StubLayeredAuth

    # Build the module hierarchy
    mod_altissimo = types.ModuleType("altissimo")
    mod_altissimo.__path__ = []  # type: ignore[attr-defined]

    mod_auth = types.ModuleType("altissimo.auth")
    mod_auth.__path__ = []  # type: ignore[attr-defined]

    mod_core = types.ModuleType("altissimo.auth.core")
    mod_core.__path__ = []  # type: ignore[attr-defined]

    mod_models = types.ModuleType("altissimo.auth.core.models")
    mod_exceptions = types.ModuleType("altissimo.auth.core.exceptions")
    mod_telemetry = types.ModuleType("altissimo.auth.core.telemetry")
    mod_ninja = types.ModuleType("altissimo.auth.ninja")
    mod_cascade = types.ModuleType("altissimo.auth.cascade")
    mod_service = types.ModuleType("altissimo.auth.service")

    # --- Populate models ---
    mod_models.APIKeyRecord = APIKeyRecord  # type: ignore[attr-defined]
    mod_models.FirebaseUser = FirebaseUser  # type: ignore[attr-defined]
    mod_models.GoogleUser = GoogleUser  # type: ignore[attr-defined]
    mod_models.IAPIdentity = IAPIdentity  # type: ignore[attr-defined]
    mod_models.AuthSource = AuthSource  # type: ignore[attr-defined]
    mod_models.AuthReasonCode = AuthReasonCode  # type: ignore[attr-defined]

    # --- Populate exceptions ---
    mod_exceptions.AuthError = AuthError  # type: ignore[attr-defined]
    mod_exceptions.AuthUnauthorizedError = AuthUnauthorizedError  # type: ignore[attr-defined]
    mod_exceptions.AuthForbiddenError = AuthForbiddenError  # type: ignore[attr-defined]
    mod_exceptions.AuthNotFoundError = AuthNotFoundError  # type: ignore[attr-defined]

    # --- Populate telemetry (no-op) ---
    mod_telemetry.log_auth_event = lambda **kwargs: None  # type: ignore[attr-defined]

    # --- Populate ninja adapter ---
    mod_ninja.ApiKeyAuth = api_key_cls  # type: ignore[attr-defined]
    mod_ninja.ApiKeyHeaderAuth = api_key_cls  # type: ignore[attr-defined]
    mod_ninja.ApiKeyQueryAuth = api_key_cls  # type: ignore[attr-defined]
    mod_ninja.FirebaseAuth = firebase_cls  # type: ignore[attr-defined]
    mod_ninja.FirebaseAdminAuth = firebase_cls  # type: ignore[attr-defined]
    mod_ninja.GoogleAuth = google_cls  # type: ignore[attr-defined]
    mod_ninja.GoogleAdminAuth = google_cls  # type: ignore[attr-defined]
    mod_ninja.JWTAuth = jwt_cls  # type: ignore[attr-defined]
    mod_ninja.OIDCAuth = jwt_cls  # type: ignore[attr-defined]
    mod_ninja.LayeredAuth = layered_cls  # type: ignore[attr-defined]
    mod_ninja.configure = lambda *a, **kw: None  # type: ignore[attr-defined]
    mod_ninja._get_service = lambda: None  # type: ignore[attr-defined]

    # --- Populate cascade ---
    from .cascade import AuthCascade

    mod_cascade.AuthCascade = AuthCascade  # type: ignore[attr-defined]

    # --- Populate service (no-op) ---
    mod_service.AuthService = type(  # type: ignore[attr-defined]
        "AuthService", (), {"__init__": lambda self, **kw: None}
    )

    # --- Populate parent modules ---
    mod_core.models = mod_models  # type: ignore[attr-defined]
    mod_core.exceptions = mod_exceptions  # type: ignore[attr-defined]
    mod_core.telemetry = mod_telemetry  # type: ignore[attr-defined]
    mod_auth.core = mod_core  # type: ignore[attr-defined]
    mod_auth.ninja = mod_ninja  # type: ignore[attr-defined]
    mod_auth.cascade = mod_cascade  # type: ignore[attr-defined]
    mod_auth.service = mod_service  # type: ignore[attr-defined]
    mod_altissimo.auth = mod_auth  # type: ignore[attr-defined]

    # Re-export models at the top-level auth module (matches real package)
    mod_auth.APIKeyRecord = APIKeyRecord  # type: ignore[attr-defined]
    mod_auth.FirebaseUser = FirebaseUser  # type: ignore[attr-defined]
    mod_auth.GoogleUser = GoogleUser  # type: ignore[attr-defined]
    mod_auth.AuthSource = AuthSource  # type: ignore[attr-defined]
    mod_auth.AuthReasonCode = AuthReasonCode  # type: ignore[attr-defined]
    mod_auth.AuthError = AuthError  # type: ignore[attr-defined]
    mod_auth.AuthUnauthorizedError = AuthUnauthorizedError  # type: ignore[attr-defined]
    mod_auth.AuthForbiddenError = AuthForbiddenError  # type: ignore[attr-defined]

    # --- Wire into sys.modules ---
    modules = {
        "altissimo": mod_altissimo,
        "altissimo.auth": mod_auth,
        "altissimo.auth.core": mod_core,
        "altissimo.auth.core.models": mod_models,
        "altissimo.auth.core.exceptions": mod_exceptions,
        "altissimo.auth.core.telemetry": mod_telemetry,
        "altissimo.auth.ninja": mod_ninja,
        "altissimo.auth.cascade": mod_cascade,
        "altissimo.auth.service": mod_service,
    }
    for name, mod in modules.items():
        sys.modules[name] = mod

    return modules
