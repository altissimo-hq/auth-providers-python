"""FastAPI adapter — Depends() wrappers for auth providers.

Usage::

    from altissimo.auth.fastapi import Auth

    @router.get("", dependencies=[Depends(Auth.validate_api_key)])
    async def my_endpoint(): ...

    @router.get("/me")
    async def get_me(
        user: Annotated[FirebaseUser, Depends(Auth.validate_firebase_user)]
    ): ...
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, Annotated, Any

from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import (
    APIKeyHeader,
    APIKeyQuery,
    HTTPAuthorizationCredentials,
    HTTPBearer,
)

from ..core.exceptions import AuthForbiddenError, AuthNotFoundError, AuthUnauthorizedError
from ..core.models import AuthReasonCode, AuthSource
from ..core.telemetry import log_auth_event

if TYPE_CHECKING:
    from collections.abc import Callable

    from ..core.models import APIKeyRecord, FirebaseUser, GoogleUser, IAPIdentity
    from ..providers.jwt import JWTConfig
    from ..providers.oidc import OIDCPolicy
    from ..service import AuthService

# Security schemes
api_key_query_scheme = APIKeyQuery(name="api_key", auto_error=False)
api_key_header_scheme = APIKeyHeader(name="x-api-key", auto_error=False)

security = HTTPBearer()
Credentials = Annotated[HTTPAuthorizationCredentials, Security(security)]

optional_security = HTTPBearer(auto_error=False)
OptionalCredentials = Annotated[HTTPAuthorizationCredentials | None, Security(optional_security)]

_service: AuthService | None = None


def configure(service: AuthService) -> None:
    """Configure the FastAPI adapter with an AuthService instance.

    Call this once during application startup::

        from altissimo.auth.fastapi import configure
        from altissimo.auth.service import AuthService

        configure(AuthService(api_key_backend=my_backend))
    """
    global _service
    _service = service


def _get_service() -> AuthService:
    if _service is None:
        raise RuntimeError(
            "FastAPI auth adapter not configured. Call altissimo.auth.fastapi.configure(AuthService(...)) at startup."
        )
    return _service


class Auth:
    """FastAPI dependency collection for auth."""

    @staticmethod
    def _set_request_auth_context(
        request: Request,
        *,
        auth_source: AuthSource,
        reason_code: AuthReasonCode,
        principal_id: str | None,
        outcome: str,
        status_code: int,
    ) -> None:
        request.state.auth_context = {
            "auth_source": auth_source.value,
            "auth_outcome": outcome,
            "auth_reason_code": reason_code.value,
            "auth_status_code": status_code,
            "auth_principal_id": principal_id,
        }

    @staticmethod
    def _log_failure(
        request: Request,
        *,
        auth_source: AuthSource,
        reason_code: AuthReasonCode,
        status_code: int,
        principal_id: str | None = None,
    ) -> None:
        event = "authz.failure" if status_code == status.HTTP_403_FORBIDDEN else "authn.failure"
        log_auth_event(
            event=event,
            auth_source=auth_source.value,
            route=request.url.path,
            method=request.method,
            status_code=status_code,
            reason_code=reason_code,
            principal_id=principal_id,
        )

    @staticmethod
    def _handle_error(request: Request, *, auth_source: AuthSource, exc: Exception) -> None:
        """Map auth exceptions to HTTP responses with telemetry."""
        if isinstance(exc, AuthUnauthorizedError):
            Auth._set_request_auth_context(
                request,
                auth_source=auth_source,
                reason_code=exc.reason_code,
                principal_id=None,
                outcome="failure",
                status_code=status.HTTP_401_UNAUTHORIZED,
            )
            Auth._log_failure(
                request,
                auth_source=auth_source,
                reason_code=exc.reason_code,
                status_code=status.HTTP_401_UNAUTHORIZED,
            )
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc
        if isinstance(exc, AuthForbiddenError):
            Auth._set_request_auth_context(
                request,
                auth_source=auth_source,
                reason_code=exc.reason_code,
                principal_id=None,
                outcome="failure",
                status_code=status.HTTP_403_FORBIDDEN,
            )
            Auth._log_failure(
                request,
                auth_source=auth_source,
                reason_code=exc.reason_code,
                status_code=status.HTTP_403_FORBIDDEN,
            )
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
        if isinstance(exc, AuthNotFoundError):
            Auth._set_request_auth_context(
                request,
                auth_source=auth_source,
                reason_code=exc.reason_code,
                principal_id=None,
                outcome="failure",
                status_code=status.HTTP_404_NOT_FOUND,
            )
            Auth._log_failure(
                request,
                auth_source=auth_source,
                reason_code=exc.reason_code,
                status_code=status.HTTP_404_NOT_FOUND,
            )
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
        raise exc

    # API keys

    @staticmethod
    async def validate_api_key(
        request: Request,
        api_key_query: str | None = Depends(api_key_query_scheme),
        api_key_header: str | None = Depends(api_key_header_scheme),
    ) -> APIKeyRecord:
        """Validate API key from request header or query param."""
        try:
            api_key = _get_service().validate_api_key(api_key_header=api_key_header, api_key_query=api_key_query)
            Auth._set_request_auth_context(
                request,
                auth_source=AuthSource.API_KEY,
                reason_code=AuthReasonCode.OK,
                principal_id=api_key.id,
                outcome="success",
                status_code=status.HTTP_200_OK,
            )
            return api_key
        except Exception as exc:
            Auth._handle_error(request, auth_source=AuthSource.API_KEY, exc=exc)
            raise

    @staticmethod
    async def validate_api_key_optional(
        api_key_query: str | None = Depends(api_key_query_scheme),
        api_key_header: str | None = Depends(api_key_header_scheme),
    ) -> APIKeyRecord | None:
        """Return API key from request or None."""
        return _get_service().validate_api_key_optional(api_key_header=api_key_header, api_key_query=api_key_query)

    # Firebase

    @staticmethod
    async def validate_firebase_user(
        request: Request,
        credentials: Credentials,
    ) -> FirebaseUser:
        """Validate Firebase bearer token."""
        try:
            user = _get_service().validate_firebase_user(credentials.credentials)
            Auth._set_request_auth_context(
                request,
                auth_source=AuthSource.FIREBASE,
                reason_code=AuthReasonCode.OK,
                principal_id=user.uid,
                outcome="success",
                status_code=status.HTTP_200_OK,
            )
            return user
        except Exception as exc:
            Auth._handle_error(request, auth_source=AuthSource.FIREBASE, exc=exc)
            raise

    @staticmethod
    async def validate_firebase_admin(
        request: Request,
        credentials: Credentials,
    ) -> FirebaseUser:
        """Validate Firebase admin bearer token."""
        try:
            user = _get_service().validate_firebase_admin(credentials.credentials)
            Auth._set_request_auth_context(
                request,
                auth_source=AuthSource.FIREBASE,
                reason_code=AuthReasonCode.OK,
                principal_id=user.uid,
                outcome="success",
                status_code=status.HTTP_200_OK,
            )
            return user
        except Exception as exc:
            Auth._handle_error(request, auth_source=AuthSource.FIREBASE, exc=exc)
            raise

    # Google OAuth2

    @staticmethod
    async def validate_google_user(
        request: Request,
        credentials: Credentials,
    ) -> GoogleUser:
        """Validate Google OAuth2 bearer token."""
        try:
            user = _get_service().validate_google_user(credentials.credentials)
            Auth._set_request_auth_context(
                request,
                auth_source=AuthSource.GOOGLE,
                reason_code=AuthReasonCode.OK,
                principal_id=user.id,
                outcome="success",
                status_code=status.HTTP_200_OK,
            )
            return user
        except Exception as exc:
            Auth._handle_error(request, auth_source=AuthSource.GOOGLE, exc=exc)
            raise

    @staticmethod
    async def validate_google_admin(
        request: Request,
        credentials: Credentials,
    ) -> GoogleUser:
        """Validate Google OAuth2 admin bearer token."""
        try:
            user = _get_service().validate_google_admin(credentials.credentials)
            Auth._set_request_auth_context(
                request,
                auth_source=AuthSource.GOOGLE,
                reason_code=AuthReasonCode.OK,
                principal_id=user.id,
                outcome="success",
                status_code=status.HTTP_200_OK,
            )
            return user
        except Exception as exc:
            Auth._handle_error(request, auth_source=AuthSource.GOOGLE, exc=exc)
            raise

    # OIDC service account

    @staticmethod
    def create_oidc_dependency(policy: OIDCPolicy) -> Callable:
        """Return a FastAPI dependency for OIDC service account auth.

        Usage::

            verify_caller = Auth.create_oidc_dependency(MY_POLICY)

            @router.post("", dependencies=[Depends(verify_caller)])
            async def my_endpoint(): ...
        """

        async def _dependency(
            request: Request,
            credentials: Credentials,
        ) -> str:
            env = os.environ.get("ENV", "dev")
            try:
                email = _get_service().validate_service_account_token(credentials.credentials, env, policy)
                Auth._set_request_auth_context(
                    request,
                    auth_source=AuthSource.SERVICE_ACCOUNT,
                    reason_code=AuthReasonCode.OK,
                    principal_id=email,
                    outcome="success",
                    status_code=status.HTTP_200_OK,
                )
                return email
            except AuthUnauthorizedError as exc:
                if exc.reason_code == AuthReasonCode.AUTH_SERVICE_UNAVAILABLE:
                    Auth._set_request_auth_context(
                        request,
                        auth_source=AuthSource.SERVICE_ACCOUNT,
                        reason_code=exc.reason_code,
                        principal_id=None,
                        outcome="failure",
                        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    )
                    raise HTTPException(
                        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                        detail=str(exc),
                    ) from exc
                Auth._handle_error(request, auth_source=AuthSource.SERVICE_ACCOUNT, exc=exc)
                raise
            except Exception as exc:
                Auth._handle_error(request, auth_source=AuthSource.SERVICE_ACCOUNT, exc=exc)
                raise

        return _dependency

    # JWT

    @staticmethod
    def create_jwt_dependency(config: JWTConfig) -> Callable:
        """Return a FastAPI dependency for generic JWT verification."""

        async def _dependency(
            request: Request,
            credentials: Credentials,
        ) -> dict[str, Any]:
            try:
                payload = _get_service().validate_jwt(credentials.credentials, config)
                Auth._set_request_auth_context(
                    request,
                    auth_source=AuthSource.JWT,
                    reason_code=AuthReasonCode.OK,
                    principal_id=payload.get("sub"),
                    outcome="success",
                    status_code=status.HTTP_200_OK,
                )
                return payload
            except Exception as exc:
                Auth._handle_error(request, auth_source=AuthSource.JWT, exc=exc)
                raise

        return _dependency

    # IAP

    @staticmethod
    async def get_iap_identity(request: Request) -> IAPIdentity:
        """Extract IAP identity from request headers."""
        return _get_service().get_iap_identity(dict(request.headers))

    # Webhooks

    @staticmethod
    def verify_webhook(
        request: Request,
        *,
        payload: str | bytes,
        signature: str,
    ) -> Any:
        """Verify webhook payload/signature."""
        try:
            result = _get_service().verify_webhook(payload, signature)
            Auth._set_request_auth_context(
                request,
                auth_source=AuthSource.WEBHOOK,
                reason_code=AuthReasonCode.OK,
                principal_id=None,
                outcome="success",
                status_code=status.HTTP_200_OK,
            )
            return result
        except Exception as exc:
            Auth._handle_error(request, auth_source=AuthSource.WEBHOOK, exc=exc)
            raise


# Convenience aliases
validate_api_key = Auth.validate_api_key
validate_api_key_optional = Auth.validate_api_key_optional
validate_firebase_user = Auth.validate_firebase_user
validate_firebase_admin = Auth.validate_firebase_admin
validate_google_user = Auth.validate_google_user
validate_google_admin = Auth.validate_google_admin
create_oidc_dependency = Auth.create_oidc_dependency
create_jwt_dependency = Auth.create_jwt_dependency
get_iap_identity = Auth.get_iap_identity
verify_webhook = Auth.verify_webhook
