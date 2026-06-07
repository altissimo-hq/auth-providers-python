"""Flask adapter — Google OAuth2 server-side flow support."""

from __future__ import annotations

import json
import urllib.request
from enum import StrEnum
from functools import wraps
from typing import TYPE_CHECKING, Any

from flask import g, redirect, request, session, url_for
from google.auth.transport import requests
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow

from ..core.exceptions import AuthUnauthorizedError
from ..core.models import AuthReasonCode, GoogleUser

if TYPE_CHECKING:
    from collections.abc import Callable

    from werkzeug.wrappers import Response


class SessionValidationMethod(StrEnum):
    """How to validate the OAuth2 session."""

    ID_TOKEN = "id_token"
    ACCESS_TOKEN = "access_token"


class OAuth2FlowManager:
    """Manages Google OAuth2 server-side authorization code flow for Flask applications."""

    def __init__(
        self,
        *,
        client_secrets_file: str | None = None,
        client_config: dict[str, Any] | None = None,
        scopes: list[str],
        redirect_uri_endpoint: str = "oauth2_callback",
        hosted_domain: str | None = None,
        session_validation_method: SessionValidationMethod = SessionValidationMethod.ID_TOKEN,
        access_token_info_url: str = "https://www.googleapis.com/oauth2/v3/tokeninfo",
    ) -> None:
        """Initialize the flow manager.

        Must provide either client_secrets_file or client_config, but not both.
        """
        if bool(client_secrets_file) == bool(client_config):
            raise ValueError("Must provide exactly one of client_secrets_file or client_config")

        self.client_secrets_file = client_secrets_file
        self.client_config = client_config
        self.scopes = scopes
        self.redirect_uri_endpoint = redirect_uri_endpoint
        self.hosted_domain = hosted_domain
        self.session_validation_method = session_validation_method
        self.access_token_info_url = access_token_info_url

    def get_flow(self) -> Flow:
        """Create and return the Google OAuth2 flow instance."""
        if self.client_secrets_file:
            flow = Flow.from_client_secrets_file(
                self.client_secrets_file,
                scopes=self.scopes,
            )
        else:
            flow = Flow.from_client_config(
                self.client_config,
                scopes=self.scopes,
            )
        flow.redirect_uri = url_for(self.redirect_uri_endpoint, _external=True)
        return flow

    def login_redirect(self) -> Response:
        """Generate the authorization URL and redirect the user."""
        flow = self.get_flow()
        authorization_url, state = flow.authorization_url(
            access_type="offline",
            include_granted_scopes="true",
            prompt="consent",
            hd=self.hosted_domain,
        )
        session["oauth_state"] = state
        return redirect(authorization_url)

    def _extract_user_from_id_token(self, credentials: Any) -> dict[str, Any]:
        if not credentials.id_token:
            raise AuthUnauthorizedError("No ID token provided", reason_code=AuthReasonCode.INVALID_GOOGLE_TOKEN)

        id_info = id_token.verify_oauth2_token(
            credentials.id_token,
            requests.Request(),
            audience=credentials.client_id,
        )

        if self.hosted_domain and id_info.get("hd") != self.hosted_domain:
            raise AuthUnauthorizedError(
                "Domain not authorized",
                reason_code=AuthReasonCode.INVALID_GOOGLE_TOKEN,
            )

        return {
            "id": id_info.get("sub"),
            "email": id_info.get("email"),
            "hd": id_info.get("hd"),
        }

    def _extract_user_from_access_token(self, credentials: Any) -> dict[str, Any]:
        if not credentials.token:
            raise AuthUnauthorizedError("No access token provided", reason_code=AuthReasonCode.INVALID_GOOGLE_TOKEN)

        url = f"{self.access_token_info_url}?access_token={credentials.token}"
        try:
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=10) as response:
                id_info = json.loads(response.read().decode())
        except Exception as e:
            raise AuthUnauthorizedError("Invalid access token", reason_code=AuthReasonCode.INVALID_GOOGLE_TOKEN) from e

        if self.hosted_domain and id_info.get("hd") != self.hosted_domain:
            raise AuthUnauthorizedError(
                "Domain not authorized",
                reason_code=AuthReasonCode.INVALID_GOOGLE_TOKEN,
            )

        return {
            "id": id_info.get("sub"),
            "email": id_info.get("email"),
            "hd": id_info.get("hd"),
        }

    def handle_callback(self) -> dict[str, Any]:
        """Handle the OAuth2 callback, fetching tokens and storing them in the session."""
        state = session.get("oauth_state")
        if not state or state != request.args.get("state"):
            raise AuthUnauthorizedError("Invalid state parameter", reason_code=AuthReasonCode.INVALID_GOOGLE_TOKEN)

        flow = self.get_flow()
        flow.fetch_token(authorization_response=request.url)
        credentials = flow.credentials

        if self.session_validation_method == SessionValidationMethod.ID_TOKEN:
            user_info = self._extract_user_from_id_token(credentials)
        else:
            user_info = self._extract_user_from_access_token(credentials)

        # Store credentials in session
        session["google_token"] = credentials.token
        session["google_refresh_token"] = credentials.refresh_token
        session["google_id_token"] = credentials.id_token
        session["google_client_id"] = credentials.client_id
        # Explicitly avoid storing client_secret to avoid security risk
        session.pop("google_client_secret", None)
        session["user_info"] = user_info

        return user_info

    def validate_session(self) -> dict[str, Any] | None:
        """Re-verify the stored token. Returns user_info or None."""
        user_info = session.get("user_info")
        if not user_info:
            return None

        if self.session_validation_method == SessionValidationMethod.ID_TOKEN:
            id_tok = session.get("google_id_token")
            client_id = session.get("google_client_id")
            if not id_tok or not client_id:
                return None
            try:
                id_info = id_token.verify_oauth2_token(
                    id_tok,
                    requests.Request(),
                    audience=client_id,
                )
                if self.hosted_domain and id_info.get("hd") != self.hosted_domain:
                    return None
                if id_info.get("sub") != user_info["id"]:
                    return None
                return user_info
            except Exception:
                return None
        else:
            access_tok = session.get("google_token")
            if not access_tok:
                return None
            try:
                url = f"{self.access_token_info_url}?access_token={access_tok}"
                req = urllib.request.Request(url)
                with urllib.request.urlopen(req, timeout=10) as response:
                    id_info = json.loads(response.read().decode())
                if self.hosted_domain and id_info.get("hd") != self.hosted_domain:
                    return None
                if id_info.get("sub") != user_info["id"]:
                    return None
                return user_info
            except Exception:
                return None

    def logout(self) -> None:
        """Clear the auth session data."""
        keys_to_clear = [
            "oauth_state",
            "google_token",
            "google_refresh_token",
            "google_id_token",
            "google_client_id",
            "user_info",
        ]
        for key in keys_to_clear:
            session.pop(key, None)

    def require_auth(self, f: Callable[..., Any]) -> Callable[..., Any]:
        """Decorator to require authentication for a Flask route."""

        @wraps(f)
        def decorated_function(*args: Any, **kwargs: Any) -> Any:
            user_info = self.validate_session()
            if not user_info:
                # Redirect to login or return 401 based on content type
                if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
                    raise AuthUnauthorizedError("Not authenticated", reason_code=AuthReasonCode.INVALID_GOOGLE_TOKEN)
                return self.login_redirect()

            # Set user in flask.g for access within the route
            g.user = GoogleUser(
                id=user_info["id"],
                email=user_info["email"],
                hd=user_info.get("hd"),
                admin=False,
            )
            return f(*args, **kwargs)

        return decorated_function
