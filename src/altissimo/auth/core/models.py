"""Auth models.

Framework-agnostic Pydantic models shared across all auth providers and adapters.
"""

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator


class AuthSource(StrEnum):
    """Supported auth sources."""

    API_KEY = "api_key"
    FIREBASE = "firebase"
    GOOGLE = "google"
    IAP = "iap"
    SERVICE_ACCOUNT = "service_account"
    WEBHOOK = "webhook"


class AuthReasonCode(StrEnum):
    """Stable reason codes for auth decisions."""

    OK = "ok"

    # API key
    MISSING_API_KEY = "missing_api_key"
    INVALID_API_KEY = "invalid_api_key"

    # Google OAuth2
    INVALID_GOOGLE_TOKEN = "invalid_google_token"

    # Firebase
    INVALID_FIREBASE_TOKEN = "invalid_firebase_token"
    EXPIRED_FIREBASE_TOKEN = "expired_firebase_token"
    USER_DISABLED = "user_disabled"

    # Authorization
    NOT_ADMIN = "not_admin"

    # OIDC service account
    INVALID_OIDC_TOKEN = "invalid_oidc_token"
    UNAUTHORIZED_CALLER = "unauthorized_caller"
    AUTH_SERVICE_UNAVAILABLE = "auth_service_unavailable"

    # Webhooks
    INVALID_WEBHOOK_SIGNATURE = "invalid_webhook_signature"
    INVALID_WEBHOOK_PAYLOAD = "invalid_webhook_payload"


class AuthPrincipal(BaseModel):
    """Normalized authenticated principal."""

    source: AuthSource
    subject: str
    email: EmailStr | None = None
    admin: bool = False


class GoogleTokenInfo(BaseModel):
    """Google OAuth2 ID token payload."""

    iss: str
    azp: str
    aud: str
    sub: str
    hd: str | None = None
    email: EmailStr
    email_verified: bool
    at_hash: str | None = None
    nbf: datetime | None = None
    iat: datetime
    exp: datetime
    jlt: str | None = None
    alg: str | None = None
    kid: str | None = None
    typ: str | None = None

    model_config = ConfigDict(extra="allow")

    @field_validator("email", mode="before")
    @classmethod
    def lowercase_email(cls, value: Any) -> Any:
        """Normalize email casing."""
        return value.lower() if isinstance(value, str) else value


class GoogleUser(BaseModel):
    """Authenticated Google API user."""

    id: str
    email: EmailStr
    hd: str | None = None
    admin: bool = False

    model_config = ConfigDict(extra="allow")

    @field_validator("email", mode="before")
    @classmethod
    def lowercase_email(cls, value: Any) -> Any:
        """Normalize email casing."""
        return value.lower() if isinstance(value, str) else value


class IAPIdentity(BaseModel):
    """Identity extracted from Google IAP headers."""

    email: str | None = None
    user_id: str | None = None


class FirebaseUser(BaseModel):
    """Firebase user record.

    Pydantic representation of a firebase_admin UserRecord, decoupled from
    the firebase-admin SDK so consumers don't need to depend on it directly.
    """

    uid: str
    email: str | None = None
    email_verified: bool = False
    disabled: bool = False
    display_name: str | None = None
    phone_number: str | None = None
    photo_url: str | None = None
    provider_id: str | None = None
    tenant_id: str | None = None
    tokens_valid_after_timestamp: str | None = None
    custom_claims: dict[str, Any] | None = None
    provider_data: list[dict[str, Any]] = Field(default_factory=list)

    model_config = ConfigDict(extra="allow")


class APIKeyRecord(BaseModel):
    """Represents a validated API key.

    Consumers should subclass or wrap this model to add project-specific fields
    (e.g. scopes, rate limits, owner references).
    """

    id: str
    """The API key identifier."""

    model_config = ConfigDict(extra="allow")
