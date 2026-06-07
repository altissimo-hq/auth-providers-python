"""Flask adapter — Google OAuth2 server-side flow support."""

from __future__ import annotations

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


class OAuth2FlowManager:
    """Manages Google OAuth2 server-side authorization code flow for Flask applications."""

    def __init__(
        self,
        client_secrets_file: str,
        scopes: list[str],
        redirect_uri_endpoint: str = "oauth2_callback",
        hosted_domain: str | None = None,
    ) -> None:
        """Initialize the flow manager.

        Args:
            client_secrets_file: Path to Google OAuth2 client_secret.json.
            scopes: List of OAuth2 scopes to request.
            redirect_uri_endpoint: Name of the Flask endpoint for the callback.
            hosted_domain: Optional hd param to restrict login to a Google Workspace domain.
        """
        self.client_secrets_file = client_secrets_file
        self.scopes = scopes
        self.redirect_uri_endpoint = redirect_uri_endpoint
        self.hosted_domain = hosted_domain

    def get_flow(self) -> Flow:
        """Create and return the Google OAuth2 flow instance."""
        flow = Flow.from_client_secrets_file(
            self.client_secrets_file,
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

    def handle_callback(self) -> dict[str, Any]:
        """Handle the OAuth2 callback, fetching tokens and storing them in the session."""
        state = session.get("oauth_state")
        if not state or state != request.args.get("state"):
            raise AuthUnauthorizedError("Invalid state parameter", reason_code=AuthReasonCode.INVALID_GOOGLE_TOKEN)

        flow = self.get_flow()
        flow.fetch_token(authorization_response=request.url)
        credentials = flow.credentials

        # Verify the ID token to extract user info
        if not credentials.id_token:
            raise AuthUnauthorizedError("No ID token provided", reason_code=AuthReasonCode.INVALID_GOOGLE_TOKEN)

        id_info = id_token.verify_oauth2_token(
            credentials.id_token,
            requests.Request(),
            audience=credentials.client_id,
        )

        # Ensure domain matches if hosted_domain is specified
        if self.hosted_domain and id_info.get("hd") != self.hosted_domain:
            raise AuthUnauthorizedError(
                "Domain not authorized",
                reason_code=AuthReasonCode.INVALID_GOOGLE_TOKEN,
            )

        # Store credentials in session
        session["google_token"] = credentials.token
        session["google_refresh_token"] = credentials.refresh_token
        session["google_id_token"] = credentials.id_token
        session["google_client_id"] = credentials.client_id
        session["google_client_secret"] = credentials.client_secret
        session["user_info"] = {
            "id": id_info.get("sub"),
            "email": id_info.get("email"),
            "hd": id_info.get("hd"),
        }

        return session["user_info"]

    def logout(self) -> None:
        """Clear the auth session data."""
        keys_to_clear = [
            "oauth_state",
            "google_token",
            "google_refresh_token",
            "google_id_token",
            "google_client_id",
            "google_client_secret",
            "user_info",
        ]
        for key in keys_to_clear:
            session.pop(key, None)

    def require_auth(self, f: Callable[..., Any]) -> Callable[..., Any]:
        """Decorator to require authentication for a Flask route."""

        @wraps(f)
        def decorated_function(*args: Any, **kwargs: Any) -> Any:
            user_info = session.get("user_info")
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
                admin=False,  # You'd need to determine admin status separately if needed
            )
            return f(*args, **kwargs)

        return decorated_function
