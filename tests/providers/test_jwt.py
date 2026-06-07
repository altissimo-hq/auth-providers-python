from datetime import UTC, datetime, timedelta

import pytest

from altissimo.auth.core.exceptions import AuthUnauthorizedError
from altissimo.auth.core.models import AuthReasonCode
from altissimo.auth.providers.jwt import JWTConfig, JWTProvider


@pytest.fixture
def secret():
    return "super-secret"


@pytest.fixture
def config(secret):
    return JWTConfig(secret=secret, algorithms=["HS256"])


def test_create_and_verify_valid_token(config, secret):
    payload = {"sub": "user123", "custom": "data"}
    token = JWTProvider.create(payload, secret)

    verified = JWTProvider.verify(token, config)
    assert verified["sub"] == "user123"
    assert verified["custom"] == "data"


def test_decode_unverified(secret):
    payload = {"sub": "user123"}
    token = JWTProvider.create(payload, secret)

    decoded = JWTProvider.decode_unverified(token)
    assert decoded["sub"] == "user123"


def test_verify_expired_token(config, secret):
    payload = {
        "sub": "user123",
        "exp": datetime.now(UTC) - timedelta(hours=1),
    }
    token = JWTProvider.create(payload, secret)

    with pytest.raises(AuthUnauthorizedError) as exc:
        JWTProvider.verify(token, config)
    assert exc.value.reason_code == AuthReasonCode.EXPIRED_JWT


def test_verify_invalid_signature(config):
    payload = {"sub": "user123"}
    token = JWTProvider.create(payload, "wrong-secret")

    with pytest.raises(AuthUnauthorizedError) as exc:
        JWTProvider.verify(token, config)
    assert exc.value.reason_code == AuthReasonCode.INVALID_JWT


def test_verify_missing_required_claim(secret):
    config = JWTConfig(secret=secret, required_claims=["email"])
    payload = {"sub": "user123"}
    token = JWTProvider.create(payload, secret)

    with pytest.raises(AuthUnauthorizedError) as exc:
        JWTProvider.verify(token, config)
    assert exc.value.reason_code == AuthReasonCode.INVALID_JWT


def test_verify_invalid_issuer(secret):
    config = JWTConfig(secret=secret, allowed_issuers=["https://auth.example.com"])
    payload = {"sub": "user123", "iss": "https://wrong.example.com"}
    token = JWTProvider.create(payload, secret)

    with pytest.raises(AuthUnauthorizedError) as exc:
        JWTProvider.verify(token, config)
    assert exc.value.reason_code == AuthReasonCode.INVALID_JWT_ISSUER


def test_verify_missing_issuer_when_required(secret):
    config = JWTConfig(secret=secret, allowed_issuers=["https://auth.example.com"])
    payload = {"sub": "user123"}
    token = JWTProvider.create(payload, secret)

    with pytest.raises(AuthUnauthorizedError) as exc:
        JWTProvider.verify(token, config)
    assert exc.value.reason_code == AuthReasonCode.INVALID_JWT_ISSUER


def test_verify_valid_issuer(secret):
    config = JWTConfig(secret=secret, allowed_issuers=["https://auth.example.com"])
    payload = {"sub": "user123", "iss": "https://auth.example.com"}
    token = JWTProvider.create(payload, secret)

    verified = JWTProvider.verify(token, config)
    assert verified["iss"] == "https://auth.example.com"


def test_decode_unverified_invalid_token():
    with pytest.raises(AuthUnauthorizedError) as exc:
        JWTProvider.decode_unverified("invalid.token.str")
    assert exc.value.reason_code == AuthReasonCode.INVALID_JWT
