"""Tests for the API key provider."""

from __future__ import annotations

from altissimo.auth.providers.api_key import APIKeyBackend, APIKeyProvider
from tests.conftest import InMemoryKeyBackend


class TestAPIKeyProvider:
    def test_returns_none_for_none(self, api_key_backend: InMemoryKeyBackend) -> None:
        provider = APIKeyProvider(api_key_backend)
        assert provider.get_api_key(None) is None

    def test_returns_none_for_empty(self, api_key_backend: InMemoryKeyBackend) -> None:
        provider = APIKeyProvider(api_key_backend)
        assert provider.get_api_key("") is None

    def test_returns_none_for_whitespace(self, api_key_backend: InMemoryKeyBackend) -> None:
        provider = APIKeyProvider(api_key_backend)
        assert provider.get_api_key("   ") is None

    def test_returns_key_when_found(self, api_key_backend: InMemoryKeyBackend) -> None:
        provider = APIKeyProvider(api_key_backend)
        result = provider.get_api_key("valid-key-1")
        assert result is not None
        assert result.id == "valid-key-1"

    def test_strips_whitespace(self, api_key_backend: InMemoryKeyBackend) -> None:
        provider = APIKeyProvider(api_key_backend)
        result = provider.get_api_key("  valid-key-1  ")
        assert result is not None
        assert result.id == "valid-key-1"

    def test_returns_none_when_not_found(self, api_key_backend: InMemoryKeyBackend) -> None:
        provider = APIKeyProvider(api_key_backend)
        assert provider.get_api_key("nonexistent") is None


class TestAPIKeyBackendProtocol:
    def test_in_memory_satisfies_protocol(self) -> None:
        backend = InMemoryKeyBackend()
        assert isinstance(backend, APIKeyBackend)
