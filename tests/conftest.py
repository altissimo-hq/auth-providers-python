"""Shared test fixtures for altissimo-auth."""

from __future__ import annotations

import django
import pytest
from django.conf import settings

if not settings.configured:
    settings.configure()
    django.setup()

from altissimo.auth.core.models import APIKeyRecord, FirebaseUser, GoogleUser


class InMemoryKeyBackend:
    """Simple in-memory API key backend for testing."""

    def __init__(self, keys: dict[str, APIKeyRecord] | None = None) -> None:
        self._keys = keys or {}

    def get_key(self, key_id: str) -> APIKeyRecord | None:
        return self._keys.get(key_id)


@pytest.fixture
def api_key_backend() -> InMemoryKeyBackend:
    return InMemoryKeyBackend(
        {
            "valid-key-1": APIKeyRecord(id="valid-key-1"),
            "valid-key-2": APIKeyRecord(id="valid-key-2"),
        }
    )


@pytest.fixture
def google_user() -> GoogleUser:
    return GoogleUser(id="google-uid-1", email="user@example.com", hd="example.com")


@pytest.fixture
def google_admin() -> GoogleUser:
    return GoogleUser(id="google-uid-1", email="admin@example.com", hd="example.com", admin=True)


@pytest.fixture
def firebase_user() -> FirebaseUser:
    return FirebaseUser(
        uid="fb-uid-1",
        email="user@example.com",
        email_verified=True,
        disabled=False,
        custom_claims={},
    )


@pytest.fixture
def firebase_admin_user() -> FirebaseUser:
    return FirebaseUser(
        uid="fb-uid-admin",
        email="admin@example.com",
        email_verified=True,
        disabled=False,
        custom_claims={"admin": True},
    )
