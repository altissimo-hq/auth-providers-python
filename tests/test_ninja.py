from unittest.mock import MagicMock

import pytest
from django.http import HttpRequest

from altissimo.auth.core.exceptions import AuthUnauthorizedError
from altissimo.auth.core.models import APIKeyRecord, AuthReasonCode, FirebaseUser
from altissimo.auth.ninja import (
    ApiKeyHeaderAuth,
    FirebaseAuth,
    configure,
)


@pytest.fixture
def mock_service():
    service = MagicMock()
    configure(service)
    return service


@pytest.fixture
def request_factory():
    def _create_request(headers=None):
        req = HttpRequest()
        req.META = {}
        if headers:
            for k, v in headers.items():
                req.META[f"HTTP_{k.upper().replace('-', '_')}"] = v
        return req

    return _create_request


def test_api_key_header_missing(mock_service, request_factory):
    auth = ApiKeyHeaderAuth()
    req = request_factory()

    result = auth.authenticate(req, key=None)

    assert result is None
    mock_service.get_api_key.assert_not_called()


def test_api_key_header_valid(mock_service, request_factory):
    auth = ApiKeyHeaderAuth()
    req = request_factory({"X-API-KEY": "valid-key"})
    mock_service.get_api_key.return_value = APIKeyRecord(id="key-123", name="test")

    result = auth.authenticate(req, key="valid-key")

    assert result.id == "key-123"
    mock_service.get_api_key.assert_called_once_with("valid-key")


def test_api_key_header_invalid(mock_service, request_factory):
    auth = ApiKeyHeaderAuth()
    req = request_factory({"X-API-KEY": "invalid-key"})
    mock_service.get_api_key.side_effect = AuthUnauthorizedError(
        "Invalid key", reason_code=AuthReasonCode.INVALID_API_KEY
    )

    result = auth.authenticate(req, key="invalid-key")

    assert result is None
    mock_service.get_api_key.assert_called_once_with("invalid-key")


def test_firebase_valid(mock_service, request_factory):
    auth = FirebaseAuth()
    req = request_factory({"Authorization": "Bearer valid-token"})
    user = FirebaseUser(uid="user-123", email="user@example.com", email_verified=True, disabled=False, custom_claims={})
    mock_service.validate_firebase_user.return_value = user

    result = auth.authenticate(req, token="valid-token")

    assert result.uid == "user-123"
    mock_service.validate_firebase_user.assert_called_once_with("valid-token")


def test_firebase_invalid(mock_service, request_factory):
    auth = FirebaseAuth()
    req = request_factory({"Authorization": "Bearer invalid-token"})
    mock_service.validate_firebase_user.side_effect = AuthUnauthorizedError(
        "Invalid token", reason_code=AuthReasonCode.INVALID_FIREBASE_TOKEN
    )

    result = auth.authenticate(req, token="invalid-token")

    assert result is None
    mock_service.validate_firebase_user.assert_called_once_with("invalid-token")


def test_api_key_query_valid(mock_service, request_factory):
    from altissimo.auth.ninja import ApiKeyQueryAuth

    auth = ApiKeyQueryAuth()
    req = request_factory()
    req.GET = {"api_key": "query-key"}
    mock_service.get_api_key.return_value = APIKeyRecord(id="k-1", name="t")

    result = auth.authenticate(req, key="query-key")

    assert result.id == "k-1"
    mock_service.get_api_key.assert_called_once_with("query-key")


def test_api_key_query_invalid(mock_service, request_factory):
    from altissimo.auth.ninja import ApiKeyQueryAuth

    auth = ApiKeyQueryAuth()
    req = request_factory()
    req.GET = {}
    result = auth.authenticate(req, key=None)
    assert result is None

    req.GET = {"api_key": "bad"}
    mock_service.get_api_key.side_effect = AuthUnauthorizedError("err", reason_code=AuthReasonCode.INVALID_API_KEY)
    result = auth.authenticate(req, key="bad")
    assert result is None


def test_api_key_auth_combined(mock_service, request_factory):
    from altissimo.auth.ninja import ApiKeyAuth

    auth = ApiKeyAuth()
    req = request_factory({"X-API-KEY": "hdr-key"})
    req.GET = {}
    mock_service.get_api_key.return_value = APIKeyRecord(id="k-2", name="t")

    # Try header
    result = auth.authenticate(req, key="hdr-key")
    assert result.id == "k-2"

    # Try query
    req = request_factory()
    req.GET = {"api_key": "qry-key"}
    result = auth.authenticate(req, key=None)
    assert result.id == "k-2"

    # Missing
    req = request_factory()
    req.GET = {}
    result = auth.authenticate(req, key=None)
    assert result is None

    # Exception
    mock_service.get_api_key.side_effect = AuthUnauthorizedError("err", reason_code=AuthReasonCode.INVALID_API_KEY)
    result = auth.authenticate(req, key="qry-key")
    assert result is None


def test_firebase_admin(mock_service, request_factory):
    from altissimo.auth.ninja import FirebaseAdminAuth

    auth = FirebaseAdminAuth()
    req = request_factory()

    user = FirebaseUser(uid="user-123", email="user@example.com", email_verified=True, disabled=False, custom_claims={})
    mock_service.validate_firebase_admin.return_value = user
    assert auth.authenticate(req, token="valid-token").uid == "user-123"

    mock_service.validate_firebase_admin.side_effect = AuthUnauthorizedError("e", reason_code=AuthReasonCode.NOT_ADMIN)
    assert auth.authenticate(req, token="bad") is None


def test_google_auth(mock_service, request_factory):
    from altissimo.auth.core.models import GoogleUser
    from altissimo.auth.ninja import GoogleAuth

    auth = GoogleAuth()
    req = request_factory()

    user = GoogleUser(id="user1", email="u@test.com", email_verified=True, sub="sub")
    mock_service.validate_google_user.return_value = user
    assert auth.authenticate(req, token="valid-token").email == "u@test.com"

    mock_service.validate_google_user.side_effect = AuthUnauthorizedError(
        "e", reason_code=AuthReasonCode.INVALID_GOOGLE_TOKEN
    )
    assert auth.authenticate(req, token="bad") is None


def test_google_admin_auth(mock_service, request_factory):
    from altissimo.auth.core.models import GoogleUser
    from altissimo.auth.ninja import GoogleAdminAuth

    auth = GoogleAdminAuth()
    req = request_factory()

    user = GoogleUser(id="user1", email="u@test.com", email_verified=True, sub="sub")
    mock_service.validate_google_admin.return_value = user
    assert auth.authenticate(req, token="valid-token").email == "u@test.com"

    mock_service.validate_google_admin.side_effect = AuthUnauthorizedError("e", reason_code=AuthReasonCode.NOT_ADMIN)
    assert auth.authenticate(req, token="bad") is None


def test_oidc_auth(mock_service, request_factory):
    from altissimo.auth.ninja import OIDCAuth
    from altissimo.auth.providers.oidc import OIDCPolicy

    auth = OIDCAuth(policy=OIDCPolicy(valid_audiences=["aud"], allowed_callers=["c1"]), env="prod")
    req = request_factory()

    mock_service.validate_service_account_token.return_value = "c1"
    assert auth.authenticate(req, token="tok") == "c1"

    mock_service.validate_service_account_token.side_effect = AuthUnauthorizedError(
        "e", reason_code=AuthReasonCode.UNAUTHORIZED_CALLER
    )
    assert auth.authenticate(req, token="bad") is None


def test_jwt_auth(mock_service, request_factory):
    from altissimo.auth.ninja import JWTAuth
    from altissimo.auth.providers.jwt import JWTConfig

    config = JWTConfig(secret="test")
    auth = JWTAuth(config=config)
    req = request_factory()

    mock_service.validate_jwt.return_value = {"sub": "user123"}
    assert auth.authenticate(req, token="tok") == {"sub": "user123"}

    mock_service.validate_jwt.side_effect = AuthUnauthorizedError("e", reason_code=AuthReasonCode.INVALID_JWT)
    assert auth.authenticate(req, token="bad") is None


def test_get_service_unconfigured():
    import altissimo.auth.ninja as n_init
    from altissimo.auth.ninja import _get_service

    n_init._service = None
    with pytest.raises(RuntimeError):
        _get_service()


def test_log_failure_fallback(request_factory):
    from unittest.mock import patch

    from altissimo.auth.core.models import AuthReasonCode, AuthSource
    from altissimo.auth.ninja import _log_failure

    req = request_factory()
    req.path = "/test"
    req.method = "GET"

    with patch("altissimo.auth.ninja.log_auth_event") as mock_log:
        _log_failure(req, AuthSource.SERVICE_ACCOUNT)
        mock_log.assert_called_with(
            event="authn.failure",
            auth_source="service_account",
            route="/test",
            method="GET",
            status_code=401,
            reason_code=AuthReasonCode.INVALID_OIDC_TOKEN,
        )

        _log_failure(req, AuthSource.WEBHOOK)
        mock_log.assert_called_with(
            event="authn.failure",
            auth_source="webhook",
            route="/test",
            method="GET",
            status_code=401,
            reason_code=AuthReasonCode.INVALID_WEBHOOK_SIGNATURE,
        )

        _log_failure(req, AuthSource.JWT)
        mock_log.assert_called_with(
            event="authn.failure",
            auth_source="jwt",
            route="/test",
            method="GET",
            status_code=401,
            reason_code=AuthReasonCode.INVALID_JWT,
        )
