from unittest.mock import MagicMock, patch

import pytest
from flask import Flask, g, session

from altissimo.auth.core.exceptions import AuthUnauthorizedError
from altissimo.auth.flask import OAuth2FlowManager


@pytest.fixture
def app():
    app = Flask(__name__)
    app.secret_key = "test_secret_key"

    @app.route("/oauth2_callback")
    def oauth2_callback():
        return "Callback"

    return app


@pytest.fixture
def flow_manager():
    return OAuth2FlowManager(
        client_secrets_file="dummy.json",
        scopes=["openid", "email"],
        hosted_domain="example.com",
    )


def test_login_redirect(app, flow_manager):
    with (
        app.test_request_context("/login"),
        patch("altissimo.auth.flask.Flow.from_client_secrets_file") as mock_flow_cls,
    ):
        mock_flow = MagicMock()
        mock_flow.authorization_url.return_value = ("https://accounts.google.com/o/oauth2/auth", "state123")
        mock_flow_cls.return_value = mock_flow

        response = flow_manager.login_redirect()

        assert response.status_code == 302
        assert response.headers["Location"] == "https://accounts.google.com/o/oauth2/auth"
        assert session["oauth_state"] == "state123"


def test_handle_callback_success(app, flow_manager):
    with app.test_request_context("/oauth2_callback?state=state123"):
        session["oauth_state"] = "state123"

        with patch("altissimo.auth.flask.Flow.from_client_secrets_file") as mock_flow_cls:
            mock_flow = MagicMock()

            mock_credentials = MagicMock()
            mock_credentials.id_token = "mock_id_token"
            mock_credentials.token = "access_token"
            mock_credentials.refresh_token = "refresh_token"
            mock_credentials.client_id = "client_id"

            mock_flow.credentials = mock_credentials
            mock_flow_cls.return_value = mock_flow

            with patch("altissimo.auth.flask.id_token.verify_oauth2_token") as mock_verify:
                mock_verify.return_value = {
                    "sub": "12345",
                    "email": "user@example.com",
                    "hd": "example.com",
                }

                user_info = flow_manager.handle_callback()

                assert user_info["id"] == "12345"
                assert user_info["email"] == "user@example.com"
                assert session["user_info"] == user_info
                assert session["google_token"] == "access_token"


def test_handle_callback_invalid_state(app, flow_manager):
    with app.test_request_context("/oauth2_callback?state=wrong_state"):
        session["oauth_state"] = "state123"

        with pytest.raises(AuthUnauthorizedError, match="Invalid state parameter"):
            flow_manager.handle_callback()


def test_handle_callback_invalid_domain(app, flow_manager):
    with app.test_request_context("/oauth2_callback?state=state123"):
        session["oauth_state"] = "state123"

        with patch("altissimo.auth.flask.Flow.from_client_secrets_file") as mock_flow_cls:
            mock_flow = MagicMock()

            mock_credentials = MagicMock()
            mock_credentials.id_token = "mock_id_token"
            mock_flow.credentials = mock_credentials
            mock_flow_cls.return_value = mock_flow

            with patch("altissimo.auth.flask.id_token.verify_oauth2_token") as mock_verify:
                mock_verify.return_value = {
                    "sub": "12345",
                    "email": "user@otherdomain.com",
                    "hd": "otherdomain.com",
                }

                with pytest.raises(AuthUnauthorizedError, match="Domain not authorized"):
                    flow_manager.handle_callback()


def test_require_auth_decorator_redirects(app, flow_manager):
    @app.route("/protected")
    @flow_manager.require_auth
    def protected_route():
        return "Protected Data"

    with (
        app.test_request_context("/protected"),
        patch("altissimo.auth.flask.Flow.from_client_secrets_file") as mock_flow_cls,
    ):
        mock_flow = MagicMock()
        mock_flow.authorization_url.return_value = ("https://accounts.google.com/o/oauth2/auth", "state123")
        mock_flow_cls.return_value = mock_flow

        response = protected_route()

        # Since no session, it should redirect to login
        assert response.status_code == 302
        assert response.headers["Location"] == "https://accounts.google.com/o/oauth2/auth"


def test_require_auth_decorator_success(app, flow_manager):
    @app.route("/protected")
    @flow_manager.require_auth
    def protected_route():
        return f"Hello, {g.user.email}"

    with app.test_request_context("/protected"):
        session["user_info"] = {
            "id": "12345",
            "email": "user@example.com",
            "hd": "example.com",
        }

        response = protected_route()

        assert response == "Hello, user@example.com"
        assert g.user.id == "12345"
        assert g.user.email == "user@example.com"


def test_logout(app, flow_manager):
    with app.test_request_context("/logout"):
        session["oauth_state"] = "state123"
        session["user_info"] = {"id": "12345"}

        flow_manager.logout()

        assert "oauth_state" not in session
        assert "user_info" not in session
