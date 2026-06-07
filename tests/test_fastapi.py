from unittest.mock import MagicMock

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from altissimo.auth.core.exceptions import AuthUnauthorizedError
from altissimo.auth.core.models import AuthReasonCode, FirebaseUser
from altissimo.auth.fastapi import Auth, configure


@pytest.fixture
def mock_service():
    service = MagicMock()
    configure(service)
    return service


@pytest.fixture
def app():
    app = FastAPI()

    @app.get("/public")
    async def public_route():
        return {"status": "ok"}

    @app.get("/private/api-key", dependencies=[Depends(Auth.validate_api_key)])
    async def private_api_key():
        return {"status": "ok"}

    @app.get("/private/firebase")
    async def private_firebase(user: FirebaseUser = Depends(Auth.validate_firebase_user)):
        return {"status": "ok", "uid": user.uid}

    return app


@pytest.fixture
def client(app):
    return TestClient(app)


def test_api_key_missing(client, mock_service):
    mock_service.validate_api_key.side_effect = AuthUnauthorizedError(
        "Missing API key", reason_code=AuthReasonCode.MISSING_API_KEY
    )
    response = client.get("/private/api-key")
    assert response.status_code == 401
    assert "Missing API key" in response.text


def test_api_key_valid(client, mock_service):
    mock_service.validate_api_key.return_value = MagicMock(id="key-123")

    response = client.get("/private/api-key", headers={"x-api-key": "valid-key"})

    assert response.status_code == 200
    mock_service.validate_api_key.assert_called_once_with(api_key_header="valid-key", api_key_query=None)


def test_api_key_invalid(client, mock_service):
    mock_service.validate_api_key.side_effect = AuthUnauthorizedError(
        "Invalid key", reason_code=AuthReasonCode.INVALID_API_KEY
    )

    response = client.get("/private/api-key", headers={"x-api-key": "invalid-key"})

    assert response.status_code == 401
    assert "Invalid key" in response.text


def test_firebase_valid(client, mock_service):
    user = FirebaseUser(uid="user-123", email="user@example.com", email_verified=True, disabled=False, claims={})
    mock_service.validate_firebase_user.return_value = user

    response = client.get("/private/firebase", headers={"Authorization": "Bearer valid-token"})

    assert response.status_code == 200
    assert response.json()["uid"] == "user-123"
    mock_service.validate_firebase_user.assert_called_once_with("valid-token")


def test_firebase_invalid(client, mock_service):
    mock_service.validate_firebase_user.side_effect = AuthUnauthorizedError(
        "Invalid token", reason_code=AuthReasonCode.INVALID_FIREBASE_TOKEN
    )

    response = client.get("/private/firebase", headers={"Authorization": "Bearer invalid-token"})

    assert response.status_code == 401
    assert "Invalid token" in response.text
