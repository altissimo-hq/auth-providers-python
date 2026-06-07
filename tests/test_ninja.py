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
    user = FirebaseUser(uid="user-123", email="user@example.com", email_verified=True, disabled=False, claims={})
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
