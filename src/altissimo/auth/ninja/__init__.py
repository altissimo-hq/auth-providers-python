"""Django Ninja adapter — auth classes for Django Ninja routers.

Usage::

    from altissimo.auth.ninja import ApiKeyAuth, FirebaseAuth, OIDCAuth

    @api.get("", auth=ApiKeyAuth(service=my_service))
    def my_endpoint(request): ...

    @api.get("/me", auth=[FirebaseAuth(service=my_service), ApiKeyAuth(service=my_service)])
    def get_me(request): ...
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from ninja.security import APIKeyHeader as NinjaAPIKeyHeader
from ninja.security import APIKeyQuery as NinjaAPIKeyQuery
from ninja.security import HttpBearer as NinjaHttpBearer

from ..core.exceptions import AuthError
from ..core.models import AuthReasonCode, AuthSource
from ..core.telemetry import log_auth_event

if TYPE_CHECKING:
    from django.http import HttpRequest

    from ..core.models import APIKeyRecord, FirebaseUser, GoogleUser
    from ..providers.jwt import JWTConfig
    from ..providers.oidc import OIDCPolicy
    from ..service import AuthService

_service: AuthService | None = None


def configure(service: AuthService) -> None:
    """Configure the Django Ninja adapter with an AuthService instance.

    Call this once during application startup (e.g. in Django's AppConfig.ready)::

        from altissimo.auth.ninja import configure
        from altissimo.auth.service import AuthService

        configure(AuthService(api_key_backend=my_backend))
    """
    global _service
    _service = service


def _get_service() -> AuthService:
    if _service is None:
        raise RuntimeError(
            "Django Ninja auth adapter not configured. "
            "Call altissimo.auth.ninja.configure(AuthService(...)) at startup."
        )
    return _service


def _log_failure(request: HttpRequest, auth_source: AuthSource, exc: AuthError | None = None) -> None:
    """Log an auth failure using telemetry."""
    if exc:
        reason_code = exc.reason_code
    elif auth_source == AuthSource.API_KEY:
        reason_code = AuthReasonCode.MISSING_API_KEY
    else:
        # Fallbacks if a token is completely missing for a bearer source
        if auth_source == AuthSource.FIREBASE:
            reason_code = AuthReasonCode.INVALID_FIREBASE_TOKEN
        elif auth_source == AuthSource.GOOGLE:
            reason_code = AuthReasonCode.INVALID_GOOGLE_TOKEN
        elif auth_source == AuthSource.SERVICE_ACCOUNT:
            reason_code = AuthReasonCode.INVALID_OIDC_TOKEN
        elif auth_source == AuthSource.WEBHOOK:
            reason_code = AuthReasonCode.INVALID_WEBHOOK_SIGNATURE
        elif auth_source == AuthSource.JWT:
            reason_code = AuthReasonCode.INVALID_JWT
        else:
            reason_code = AuthReasonCode.INVALID_API_KEY
    log_auth_event(
        event="authn.failure",
        auth_source=auth_source.value,
        route=request.path,
        method=request.method,
        status_code=401,
        reason_code=reason_code,
    )


class ApiKeyHeaderAuth(NinjaAPIKeyHeader):
    """Authenticate via ``x-api-key`` header."""

    param_name = "x-api-key"

    def authenticate(self, request: HttpRequest, key: str | None) -> APIKeyRecord | None:
        """Return APIKeyRecord or None (Ninja treats None as auth failure)."""
        if not key:
            _log_failure(request, AuthSource.API_KEY)
            return None
        try:
            return _get_service().get_api_key(key)
        except AuthError as e:
            _log_failure(request, AuthSource.API_KEY, e)
            return None


class ApiKeyQueryAuth(NinjaAPIKeyQuery):
    """Authenticate via ``api_key`` query parameter."""

    param_name = "api_key"

    def authenticate(self, request: HttpRequest, key: str | None) -> APIKeyRecord | None:
        """Return APIKeyRecord or None."""
        if not key:
            _log_failure(request, AuthSource.API_KEY)
            return None
        try:
            return _get_service().get_api_key(key)
        except AuthError as e:
            _log_failure(request, AuthSource.API_KEY, e)
            return None


class ApiKeyAuth(NinjaAPIKeyHeader):
    """Combined API key auth — checks header first, then query param."""

    param_name = "x-api-key"

    def authenticate(self, request: HttpRequest, key: str | None) -> APIKeyRecord | None:
        """Try header, fall back to query param."""
        api_key_id = key or request.GET.get("api_key")
        if not api_key_id:
            _log_failure(request, AuthSource.API_KEY)
            return None
        try:
            return _get_service().get_api_key(api_key_id)
        except AuthError as e:
            _log_failure(request, AuthSource.API_KEY, e)
            return None


class FirebaseAuth(NinjaHttpBearer):
    """Authenticate via Firebase ID token."""

    def authenticate(self, request: HttpRequest, token: str) -> FirebaseUser | None:
        """Verify Firebase token and return user, or None on failure."""
        try:
            return _get_service().validate_firebase_user(token)
        except AuthError as e:
            _log_failure(request, AuthSource.FIREBASE, e)
            return None


class FirebaseAdminAuth(NinjaHttpBearer):
    """Authenticate via Firebase ID token and require admin claim."""

    def authenticate(self, request: HttpRequest, token: str) -> FirebaseUser | None:
        """Verify Firebase admin token."""
        try:
            return _get_service().validate_firebase_admin(token)
        except AuthError as e:
            _log_failure(request, AuthSource.FIREBASE, e)
            return None


class GoogleAuth(NinjaHttpBearer):
    """Authenticate via Google OAuth2 ID token."""

    def authenticate(self, request: HttpRequest, token: str) -> GoogleUser | None:
        """Verify Google token."""
        try:
            return _get_service().validate_google_user(token)
        except AuthError as e:
            _log_failure(request, AuthSource.GOOGLE, e)
            return None


class GoogleAdminAuth(NinjaHttpBearer):
    """Authenticate via Google OAuth2 ID token and require admin."""

    def authenticate(self, request: HttpRequest, token: str) -> GoogleUser | None:
        """Verify Google admin token."""
        try:
            return _get_service().validate_google_admin(token)
        except AuthError as e:
            _log_failure(request, AuthSource.GOOGLE, e)
            return None


class OIDCAuth(NinjaHttpBearer):
    """Authenticate via Google OIDC identity token (service-to-service).

    Usage::

        oidc_auth = OIDCAuth(policy=MY_POLICY)

        @api.post("", auth=oidc_auth)
        def my_endpoint(request): ...
    """

    def __init__(self, policy: OIDCPolicy, env: str | None = None, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._policy = policy
        self._env = env

    def authenticate(self, request: HttpRequest, token: str) -> str | None:
        """Verify OIDC token and return caller email."""
        env = self._env or os.environ.get("ENV", "dev")
        try:
            return _get_service().validate_service_account_token(token, env, self._policy)
        except AuthError as e:
            _log_failure(request, AuthSource.SERVICE_ACCOUNT, e)
            return None


class JWTAuth(NinjaHttpBearer):
    """Authenticate via generic JWT token."""

    def __init__(self, config: JWTConfig, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._config = config

    def authenticate(self, request: HttpRequest, token: str) -> dict[str, Any] | None:
        """Verify JWT token and return payload."""
        try:
            return _get_service().validate_jwt(token, self._config)
        except AuthError as e:
            _log_failure(request, AuthSource.JWT, e)
            return None


@runtime_checkable
class IdentityAuth(Protocol):
    """Protocol for identity auth providers used with :class:`LayeredAuth`.

    Any class that implements ``authenticate(request, token) -> Any | None``
    can be used as the ``identity`` parameter of :class:`LayeredAuth`.
    All built-in bearer auth classes (``FirebaseAuth``, ``GoogleAuth``,
    ``OIDCAuth``, ``JWTAuth``) satisfy this protocol.
    """

    def authenticate(self, request: Any, token: str) -> Any | None: ...  # pragma: no cover


class LayeredAuth:
    """Layered auth — required gate + optional identity enrichment.

    This implements the standard BFF (Backend-For-Frontend) pattern where
    an API key gate is always required, and a user identity (e.g. Firebase)
    is optionally checked when a Bearer token is present.

    Usage with Django Ninja::

        from altissimo.auth.ninja import LayeredAuth, ApiKeyAuth, FirebaseAuth

        public_auth = LayeredAuth(
            gate=ApiKeyAuth(),        # MUST pass — 401 if it fails
            identity=FirebaseAuth(),  # OPTIONAL — enriches request.auth if present
        )

        @api.get("/communities", auth=public_auth)
        def list_communities(request):
            user = request.auth  # FirebaseUser | None
            api_key = request.gate_auth  # APIKeyRecord
            ...

    Behavior:

    ============  ==================  ==========================================
    API Key       Bearer Token        Result
    ============  ==================  ==========================================
    ❌ Missing    —                   401 (gate failed)
    ❌ Invalid    —                   401 (gate failed)
    ✅ Valid      ❌ Not present      ``request.auth = None`` (anonymous)
    ✅ Valid      ✅ Valid Firebase   ``request.auth = FirebaseUser``
    ✅ Valid      ❌ Invalid/expired  401 (strict: bad credentials rejected)
    ============  ==================  ==========================================
    """

    # Sentinel used to signal "authenticated but anonymous" to Django Ninja.
    # Ninja treats any truthy return from __call__ as success and assigns the
    # value to request.auth.  We use a dedicated sentinel so that downstream
    # code can distinguish "anonymous via LayeredAuth" from other truthy values,
    # but request.auth is explicitly set to None in __call__ for clean ergonomics.
    _ANONYMOUS = object()

    def __init__(self, gate: Any, identity: IdentityAuth) -> None:
        """Initialize with a required gate and an optional identity auth.

        Args:
            gate: A Django Ninja auth class whose ``__call__`` returns a truthy
                value on success or ``None`` on failure. Typically an
                ``ApiKeyAuth`` instance.
            identity: Any object implementing the :class:`IdentityAuth`
                protocol (i.e. an ``authenticate(request, token)`` method).
                All built-in bearer auth classes work here, but custom
                identity providers (cookies, device tokens, etc.) are also
                supported.
        """
        self._gate = gate
        self._identity = identity

        # Expose the gate's OpenAPI security schema so Ninja's built-in schema
        # builder registers it.  For the identity scheme, users can access
        # openapi_security_schemas (plural) or register identity separately.
        if hasattr(gate, "openapi_security_schema"):
            self.openapi_security_schema = gate.openapi_security_schema

    def __call__(self, request: Any) -> Any | None:
        """Run layered authentication.

        1. Call the gate — if it returns ``None``, return ``None`` (→ 401).
        2. Check for an ``Authorization: Bearer`` header:
           - Present → delegate to ``identity.authenticate(request, token)``.
             Return the result (user object or ``None`` → 401).
           - Absent → set ``request.auth = None`` and return a truthy sentinel
             so Ninja considers auth passed (anonymous access).

        The gate result is always stashed on ``request.gate_auth``.
        """
        # --- Gate (required) ---
        gate_result = self._gate(request)
        if gate_result is None:
            return None

        # Stash gate result for downstream access
        request.gate_auth = gate_result

        # --- Identity (optional) ---
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
            if not token:
                # Empty token after "Bearer " — treat as missing
                request.auth = None
                return self._ANONYMOUS
            result = self._identity.authenticate(request, token)
            if result is None:
                # Invalid/expired token — strict rejection
                return None
            return result

        # No Bearer token — anonymous but authenticated via gate
        request.auth = None
        return self._ANONYMOUS

    @property
    def openapi_security_schemas(self) -> dict[str, Any]:
        """Return both OpenAPI security schemas keyed by class name.

        This mirrors how Django Ninja's OpenAPI builder names security
        schemes (``auth.__class__.__name__``).  Use this for programmatic
        access when you need to register both the gate and identity
        schemes manually.

        Returns:
            A dict mapping class names to their ``SecuritySchema`` dicts.
            E.g. ``{'ApiKeyAuth': {'type': 'apiKey', ...}, 'FirebaseAuth': {'type': 'http', ...}}``
        """
        schemes: dict[str, Any] = {}
        if hasattr(self._gate, "openapi_security_schema"):
            schemes[self._gate.__class__.__name__] = self._gate.openapi_security_schema
        if hasattr(self._identity, "openapi_security_schema"):
            schemes[self._identity.__class__.__name__] = self._identity.openapi_security_schema
        return schemes
