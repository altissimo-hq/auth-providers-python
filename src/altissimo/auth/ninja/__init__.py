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
from typing import TYPE_CHECKING, Any

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
