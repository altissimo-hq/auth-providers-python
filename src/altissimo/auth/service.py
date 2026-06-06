"""Auth service orchestration.

The :class:`AuthService` wires together providers and policies, offering
a single entry-point for all auth operations.  Framework adapters delegate
to this service.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .core.exceptions import AuthUnauthorizedError
from .core.models import APIKeyRecord, AuthReasonCode, FirebaseUser, GoogleUser, IAPIdentity
from .core.policies import AuthPolicyService

if TYPE_CHECKING:
    from collections.abc import Mapping

    from .providers.api_key import APIKeyBackend, APIKeyProvider
    from .providers.firebase import FirebaseAuthProvider
    from .providers.google import GoogleAuthProvider
    from .providers.iap import IAPProvider
    from .providers.oidc import OIDCPolicy, OIDCProvider
    from .providers.webhooks import WebhookProvider


class AuthService:
    """Auth orchestration service.

    All provider arguments are optional and created lazily on first use.
    Pass explicit instances for testing or custom configuration.
    """

    def __init__(
        self,
        *,
        api_key_backend: APIKeyBackend | None = None,
        api_key_provider: APIKeyProvider | None = None,
        firebase_provider: FirebaseAuthProvider | None = None,
        google_provider: GoogleAuthProvider | None = None,
        iap_provider: IAPProvider | None = None,
        oidc_provider: OIDCProvider | None = None,
        webhook_provider: WebhookProvider | None = None,
        policy_service: AuthPolicyService | None = None,
    ) -> None:
        self._api_key_backend = api_key_backend
        self._api_key_provider = api_key_provider
        self._firebase_provider = firebase_provider
        self._google_provider = google_provider
        self._iap_provider = iap_provider
        self._oidc_provider = oidc_provider
        self._webhook_provider = webhook_provider
        self._policies = policy_service or AuthPolicyService()

    # Lazy provider getters

    def _get_api_key_provider(self) -> APIKeyProvider:
        if self._api_key_provider is None:
            from .providers.api_key import APIKeyProvider

            if self._api_key_backend is None:
                raise RuntimeError(
                    "APIKeyProvider requires an APIKeyBackend. "
                    "Pass api_key_backend= or api_key_provider= to AuthService."
                )
            self._api_key_provider = APIKeyProvider(self._api_key_backend)
        return self._api_key_provider

    def _get_firebase_provider(self) -> FirebaseAuthProvider:
        if self._firebase_provider is None:
            from .providers.firebase import FirebaseAuthProvider

            self._firebase_provider = FirebaseAuthProvider()
        return self._firebase_provider

    def _get_google_provider(self) -> GoogleAuthProvider:
        if self._google_provider is None:
            from .providers.google import GoogleAuthProvider

            self._google_provider = GoogleAuthProvider()
        return self._google_provider

    def _get_iap_provider(self) -> IAPProvider:
        if self._iap_provider is None:
            from .providers.iap import IAPProvider

            self._iap_provider = IAPProvider()
        return self._iap_provider

    def _get_oidc_provider(self) -> OIDCProvider:
        if self._oidc_provider is None:
            from .providers.oidc import OIDCProvider

            self._oidc_provider = OIDCProvider()
        return self._oidc_provider

    # API keys

    def get_api_key(self, api_key_id: str | None) -> APIKeyRecord | None:
        """Return API key if present and valid, else None."""
        return self._get_api_key_provider().get_api_key(api_key_id)

    def validate_api_key(self, *, api_key_header: str | None, api_key_query: str | None) -> APIKeyRecord:
        """Validate API key and raise on missing/invalid."""
        api_key_id = api_key_header or api_key_query
        if not api_key_id or not api_key_id.strip():
            raise AuthUnauthorizedError("Missing API key", reason_code=AuthReasonCode.MISSING_API_KEY)
        api_key = self.get_api_key(api_key_id)
        if not api_key:
            raise AuthUnauthorizedError("Unauthorized", reason_code=AuthReasonCode.INVALID_API_KEY)
        return api_key

    def validate_api_key_optional(
        self, *, api_key_header: str | None, api_key_query: str | None
    ) -> APIKeyRecord | None:
        """Return API key or None (no exception)."""
        api_key_id = api_key_header or api_key_query
        return self.get_api_key(api_key_id)

    # Firebase

    def validate_firebase_user(self, bearer_token: str) -> FirebaseUser:
        """Validate Firebase user via bearer token."""
        return self._get_firebase_provider().verify_token(bearer_token)

    def validate_firebase_admin(self, bearer_token: str) -> FirebaseUser:
        """Validate Firebase admin via bearer token + custom claims."""
        user = self.validate_firebase_user(bearer_token)
        return self._policies.require_firebase_admin(user)

    # Google OAuth2

    def validate_google_user(self, bearer_token: str) -> GoogleUser:
        """Validate Google user via OAuth2 bearer token."""
        return self._get_google_provider().get_user_from_token(bearer_token)

    def validate_google_admin(self, bearer_token: str) -> GoogleUser:
        """Validate Google admin via bearer token + admin flag."""
        user = self.validate_google_user(bearer_token)
        return self._policies.require_google_admin(user)

    # OIDC service account

    def validate_service_account_token(self, token: str, env: str, policy: OIDCPolicy) -> str:
        """Validate a Google OIDC identity token. Returns caller email."""
        return self._get_oidc_provider().verify_token(token, env, policy)

    # IAP

    def get_iap_identity(self, headers: Mapping[str, str]) -> IAPIdentity:
        """Extract IAP identity from request headers."""
        return self._get_iap_provider().get_identity(headers)

    # Webhooks

    def verify_webhook(self, payload: str | bytes, signature: str) -> Any:
        """Verify webhook payload/signature via configured verifier."""
        if self._webhook_provider is None:
            raise RuntimeError("WebhookProvider not configured. Pass webhook_provider= to AuthService.")
        return self._webhook_provider.verify(payload, signature)
