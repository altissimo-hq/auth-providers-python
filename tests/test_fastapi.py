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


def test_jwt_valid(mock_service):
    from altissimo.auth.providers.jwt import JWTConfig
    config = JWTConfig(secret="test")
    app = FastAPI()

    @app.get("/test")
    async def get_test(payload: dict = Depends(Auth.create_jwt_dependency(config))):
        return payload

    client = TestClient(app)
    mock_service.validate_jwt.return_value = {"sub": "user123"}

    response = client.get("/test", headers={"Authorization": "Bearer token"})
    assert response.status_code == 200
    assert response.json() == {"sub": "user123"}


def test_jwt_invalid(mock_service):
    from altissimo.auth.providers.jwt import JWTConfig
    config = JWTConfig(secret="test")
    app = FastAPI()

    @app.get("/test")
    async def get_test(payload: dict = Depends(Auth.create_jwt_dependency(config))):
        return payload

    client = TestClient(app)
    mock_service.validate_jwt.side_effect = AuthUnauthorizedError("Bad JWT", reason_code=AuthReasonCode.INVALID_JWT)

    response = client.get("/test", headers={"Authorization": "Bearer bad-token"})
    assert response.status_code == 401
    assert response.json()["detail"] == "Bad JWT"


def test_firebase_valid(client, mock_service):
    user = FirebaseUser(uid="user-123", email="user@example.com", email_verified=True, disabled=False, custom_claims={})
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


def test_api_key_optional(mock_service):
    app = FastAPI()

    @app.get("/test")
    async def route(key=Depends(Auth.validate_api_key_optional)):
        return {"id": key.id} if key else {"id": None}

    client = TestClient(app)
    mock_service.validate_api_key_optional.return_value = None
    assert client.get("/test").json()["id"] is None

    mock_service.validate_api_key_optional.return_value = MagicMock(id="k1")
    assert client.get("/test", headers={"x-api-key": "test"}).json()["id"] == "k1"


def test_firebase_admin(mock_service):
    app = FastAPI()

    @app.get("/test")
    async def route(user=Depends(Auth.validate_firebase_admin)):
        return {"uid": user.uid}

    client = TestClient(app)
    mock_service.validate_firebase_admin.return_value = FirebaseUser(
        uid="u1", email="a@b", email_verified=True, disabled=False, custom_claims={}
    )
    assert client.get("/test", headers={"Authorization": "Bearer t"}).json()["uid"] == "u1"


def test_google_user(mock_service):
    app = FastAPI()
    from altissimo.auth.core.models import GoogleUser

    @app.get("/test")
    async def route(user=Depends(Auth.validate_google_user)):
        return {"email": user.email}

    client = TestClient(app)
    mock_service.validate_google_user.return_value = GoogleUser(
        id="user1", email="a@b.com", email_verified=True, sub="sub"
    )
    assert client.get("/test", headers={"Authorization": "Bearer t"}).json()["email"] == "a@b.com"


def test_google_admin(mock_service):
    app = FastAPI()
    from altissimo.auth.core.models import GoogleUser

    @app.get("/test")
    async def route(user=Depends(Auth.validate_google_admin)):
        return {"email": user.email}

    client = TestClient(app)
    mock_service.validate_google_admin.return_value = GoogleUser(
        id="user1", email="a@b.com", email_verified=True, sub="sub"
    )
    assert client.get("/test", headers={"Authorization": "Bearer t"}).json()["email"] == "a@b.com"


def test_oidc_dependency(mock_service):
    app = FastAPI()
    from altissimo.auth.providers.oidc import OIDCPolicy

    oidc = Auth.create_oidc_dependency(OIDCPolicy(valid_audiences=["aud"], allowed_callers=["a@b.com"]))

    @app.get("/test")
    async def route(caller=Depends(oidc)):
        return {"caller": caller}

    client = TestClient(app)
    mock_service.validate_service_account_token.return_value = "a@b.com"
    assert client.get("/test", headers={"Authorization": "Bearer t"}).json()["caller"] == "a@b.com"


def test_iap_identity(mock_service):
    app = FastAPI()
    from altissimo.auth.core.models import IAPIdentity

    @app.get("/test")
    async def route(identity=Depends(Auth.get_iap_identity)):
        return {"email": identity.email}

    client = TestClient(app)
    mock_service.get_iap_identity.return_value = IAPIdentity(email="a@b.com", sub="sub")
    assert client.get("/test", headers={"X-Goog-IAP-JWT-Assertion": "t"}).json()["email"] == "a@b.com"


def test_webhook(mock_service):
    from fastapi import Request

    from altissimo.auth.fastapi import Auth

    mock_req = MagicMock(spec=Request)
    mock_service.verify_webhook.return_value = {"ok": True}

    result = Auth.verify_webhook(mock_req, payload=b"body", signature="sig")
    assert result["ok"] is True
    mock_service.verify_webhook.assert_called_with(b"body", "sig")


def test_handle_error_mappings(mock_service):
    from altissimo.auth.core.exceptions import AuthForbiddenError, AuthNotFoundError
    from altissimo.auth.core.models import AuthReasonCode
    from altissimo.auth.fastapi import Auth

    app = FastAPI()

    @app.get("/forbidden")
    async def route_forbidden(user=Depends(Auth.validate_api_key)):
        pass

    @app.get("/notfound")
    async def route_notfound(user=Depends(Auth.validate_api_key)):
        pass

    client = TestClient(app)

    mock_service.validate_api_key.side_effect = AuthForbiddenError("f", reason_code=AuthReasonCode.NOT_ADMIN)
    assert client.get("/forbidden").status_code == 403

    mock_service.validate_api_key.side_effect = AuthNotFoundError("n", reason_code=AuthReasonCode.NOT_ADMIN)
    assert client.get("/notfound").status_code == 404


def test_get_service_unconfigured():
    import altissimo.auth.fastapi as f_init
    from altissimo.auth.fastapi import _get_service

    f_init._service = None
    with pytest.raises(RuntimeError):
        _get_service()
