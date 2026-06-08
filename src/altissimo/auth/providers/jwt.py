"""Generic JWT provider for verifying tokens from arbitrary identity systems."""

from dataclasses import dataclass, field
from typing import Any

import jwt
from jwt.exceptions import (
    DecodeError,
    ExpiredSignatureError,
    ImmatureSignatureError,
    InvalidAlgorithmError,
    InvalidIssuerError,
    InvalidSignatureError,
    InvalidTokenError,
    MissingRequiredClaimError,
)

from ..core.exceptions import AuthUnauthorizedError
from ..core.models import AuthReasonCode


@dataclass(frozen=True)
class JWTConfig:
    """Configuration for JWT verification."""

    secret: str
    algorithms: list[str] = field(default_factory=lambda: ["HS256"])
    allowed_issuers: list[str] | None = None
    required_claims: list[str] | None = None
    audience: str | list[str] | None = None
    options: dict[str, Any] | None = None


class JWTProvider:
    """Framework-agnostic JWT verification."""

    @staticmethod
    def verify(token: str, config: JWTConfig) -> dict[str, Any]:
        """Verify a JWT signature and claims using PyJWT.

        Raises:
            AuthUnauthorizedError: If verification fails, mapped to specific reason codes.
        """
        options = config.options.copy() if config.options else {}
        if config.required_claims:
            options["require"] = config.required_claims

        try:
            payload = jwt.decode(
                token,
                config.secret,
                algorithms=config.algorithms,
                audience=config.audience,
                options=options,
            )
        except ExpiredSignatureError as e:
            raise AuthUnauthorizedError(str(e), reason_code=AuthReasonCode.EXPIRED_JWT) from e
        except InvalidIssuerError as e:
            raise AuthUnauthorizedError(str(e), reason_code=AuthReasonCode.INVALID_JWT_ISSUER) from e
        except (
            InvalidSignatureError,
            InvalidAlgorithmError,
            MissingRequiredClaimError,
            ImmatureSignatureError,
            DecodeError,
            InvalidTokenError,
        ) as e:
            raise AuthUnauthorizedError(str(e), reason_code=AuthReasonCode.INVALID_JWT) from e
        except Exception as e:
            raise AuthUnauthorizedError(
                f"JWT verification failed: {e!s}", reason_code=AuthReasonCode.INVALID_JWT
            ) from e

        if config.allowed_issuers:
            issuer = payload.get("iss")
            if not issuer or issuer not in config.allowed_issuers:
                raise AuthUnauthorizedError(f"Invalid issuer: {issuer}", reason_code=AuthReasonCode.INVALID_JWT_ISSUER)

        return payload

    @staticmethod
    def decode_unverified(token: str) -> dict[str, Any]:
        """Decode a JWT without verifying the signature.

        WARNING: Should never be used for authorization decisions.
        """
        try:
            return jwt.decode(token, options={"verify_signature": False})
        except Exception as e:
            raise AuthUnauthorizedError(f"JWT decode failed: {e!s}", reason_code=AuthReasonCode.INVALID_JWT) from e

    @staticmethod
    def create(payload: dict[str, Any], secret: str, algorithm: str = "HS256") -> str:
        """Create a signed JWT token."""
        return jwt.encode(payload, secret, algorithm=algorithm)
