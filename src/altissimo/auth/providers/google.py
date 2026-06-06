"""Google OAuth2 authentication provider.

Verifies Google OAuth2 ID tokens using the ``google-auth`` library.
The ``google-auth`` package is an optional dependency — import this
module only when the ``[google]`` extra is installed.
"""

from google.auth.exceptions import InvalidValue, MalformedError
from google.auth.transport import requests
from google.oauth2 import id_token

from ..core.exceptions import AuthUnauthorizedError, GoogleTokenVerificationError
from ..core.models import AuthReasonCode, GoogleTokenInfo, GoogleUser


class GoogleAuthProvider:
    """Google OAuth2 ID token verification."""

    @staticmethod
    def verify_google_id_token(google_id_token: str) -> GoogleTokenInfo:
        """Verify and decode a Google OAuth2 ID token.

        Raises:
            GoogleTokenVerificationError: Token is malformed or invalid.
            ValueError: Token issuer is not Google.
        """

        try:
            token_info = id_token.verify_oauth2_token(google_id_token, requests.Request())
        except MalformedError as exc:
            raise GoogleTokenVerificationError(f"Malformed Header: {exc}") from exc
        except InvalidValue as exc:
            raise GoogleTokenVerificationError(f"Invalid Value: {exc}") from exc

        if token_info["iss"] not in (
            "accounts.google.com",
            "https://accounts.google.com",
        ):
            raise ValueError("Invalid issuer.")

        return GoogleTokenInfo(**token_info)

    @classmethod
    def get_user_from_token(cls, google_id_token: str) -> GoogleUser:
        """Verify a Google ID token and return a GoogleUser.

        This method only verifies the token and extracts identity.
        Admin status is **not** resolved here — that is the consumer's
        responsibility (e.g. via a database lookup).

        Raises:
            AuthUnauthorizedError: Token verification failed.
        """
        try:
            token_info = cls.verify_google_id_token(google_id_token)
        except (GoogleTokenVerificationError, ValueError) as exc:
            raise AuthUnauthorizedError(str(exc), reason_code=AuthReasonCode.INVALID_GOOGLE_TOKEN) from exc

        return GoogleUser(
            id=token_info.sub,
            email=token_info.email,
            hd=token_info.hd,
        )
