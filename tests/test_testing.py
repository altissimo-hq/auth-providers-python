"""Tests for altissimo.auth.testing module."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from altissimo.auth.core.models import APIKeyRecord, FirebaseUser
from altissimo.auth.testing import (
    StubApiKeyAuth,
    StubFirebaseAuth,
    StubGoogleAuth,
    StubJWTAuth,
    StubLayeredAuth,
)

# ---------------------------------------------------------------------------
# StubApiKeyAuth
# ---------------------------------------------------------------------------


class TestStubApiKeyAuth:
    def test_default_authenticate_raises(self):
        """Default authenticate() raises NotImplementedError."""
        auth = StubApiKeyAuth()
        with pytest.raises(NotImplementedError):
            auth.authenticate(MagicMock(), "some-key")

    def test_call_extracts_header_key(self):
        """__call__ extracts key from headers and passes to authenticate."""

        class MyAuth(StubApiKeyAuth):
            def authenticate(self, request, key):
                return APIKeyRecord(id=key) if key else None

        auth = MyAuth()
        req = SimpleNamespace(
            headers={"X-API-Key": "valid-key"},
            META={},
            GET={},
        )
        result = auth(req)
        assert result is not None
        assert result.id == "valid-key"

    def test_call_falls_back_to_query_param(self):
        """__call__ falls back to api_key query param."""

        class MyAuth(StubApiKeyAuth):
            def authenticate(self, request, key):
                return APIKeyRecord(id=key) if key else None

        auth = MyAuth()
        req = SimpleNamespace(
            headers={},
            META={},
            GET={"api_key": "query-key"},
        )
        result = auth(req)
        assert result is not None
        assert result.id == "query-key"

    def test_call_returns_none_when_no_key(self):
        """__call__ returns None when no key is found."""

        class MyAuth(StubApiKeyAuth):
            def authenticate(self, request, key):
                return APIKeyRecord(id=key) if key else None

        auth = MyAuth()
        req = SimpleNamespace(headers={}, META={}, GET={})
        assert auth(req) is None

    def test_has_openapi_security_schema(self):
        auth = StubApiKeyAuth()
        assert auth.openapi_security_schema["type"] == "apiKey"


# ---------------------------------------------------------------------------
# StubFirebaseAuth
# ---------------------------------------------------------------------------


class TestStubFirebaseAuth:
    def test_always_denies(self):
        auth = StubFirebaseAuth()
        assert auth.authenticate(MagicMock(), "token") is None
        assert auth(MagicMock()) is None

    def test_has_openapi_security_schema(self):
        auth = StubFirebaseAuth()
        assert auth.openapi_security_schema["type"] == "http"
        assert auth.openapi_security_schema["scheme"] == "bearer"


# ---------------------------------------------------------------------------
# StubGoogleAuth
# ---------------------------------------------------------------------------


class TestStubGoogleAuth:
    def test_always_denies(self):
        auth = StubGoogleAuth()
        assert auth.authenticate(MagicMock(), "token") is None
        assert auth(MagicMock()) is None


# ---------------------------------------------------------------------------
# StubJWTAuth
# ---------------------------------------------------------------------------


class TestStubJWTAuth:
    def test_always_denies(self):
        auth = StubJWTAuth()
        assert auth.authenticate(MagicMock(), "token") is None
        assert auth(MagicMock()) is None

    def test_accepts_kwargs(self):
        """Matches JWTAuth(config=...) constructor signature."""
        auth = StubJWTAuth(config="ignored")
        assert auth is not None


# ---------------------------------------------------------------------------
# StubLayeredAuth
# ---------------------------------------------------------------------------


class TestStubLayeredAuth:
    def test_gate_fail_returns_none(self):
        gate = MagicMock(return_value=None)
        identity = StubFirebaseAuth()
        auth = StubLayeredAuth(gate=gate, identity=identity)

        req = SimpleNamespace(headers={}, META={}, GET={})
        assert auth(req) is None

    def test_gate_pass_no_bearer(self):
        gate = MagicMock(return_value=APIKeyRecord(id="k1"))
        identity = StubFirebaseAuth()
        auth = StubLayeredAuth(gate=gate, identity=identity)

        req = SimpleNamespace(headers={}, META={}, GET={})
        result = auth(req)
        assert result is not None  # truthy sentinel
        assert req.auth is None  # anonymous
        assert req.gate_auth.id == "k1"

    def test_gate_pass_valid_bearer(self):
        gate = MagicMock(return_value=APIKeyRecord(id="k1"))
        user = FirebaseUser(uid="u1", email="u@test.com", email_verified=True, disabled=False)
        identity = MagicMock()
        identity.authenticate = MagicMock(return_value=user)
        auth = StubLayeredAuth(gate=gate, identity=identity)

        req = SimpleNamespace(headers={"Authorization": "Bearer valid-token"}, META={}, GET={})
        result = auth(req)
        assert result.uid == "u1"
        identity.authenticate.assert_called_once_with(req, "valid-token")

    def test_gate_pass_bad_bearer(self):
        gate = MagicMock(return_value=APIKeyRecord(id="k1"))
        identity = MagicMock()
        identity.authenticate = MagicMock(return_value=None)
        auth = StubLayeredAuth(gate=gate, identity=identity)

        req = SimpleNamespace(headers={"Authorization": "Bearer bad-token"}, META={}, GET={})
        assert auth(req) is None


# ---------------------------------------------------------------------------
# install_test_modules
# ---------------------------------------------------------------------------


class TestInstallTestModules:
    def test_installs_modules(self):
        """install_test_modules wires stubs into sys.modules."""
        import sys

        from altissimo.auth.testing import install_test_modules

        # Save originals
        saved = {}
        keys_to_watch = [
            "altissimo",
            "altissimo.auth",
            "altissimo.auth.ninja",
            "altissimo.auth.core",
            "altissimo.auth.core.models",
            "altissimo.auth.core.exceptions",
            "altissimo.auth.core.telemetry",
            "altissimo.auth.cascade",
            "altissimo.auth.service",
        ]
        for k in keys_to_watch:
            saved[k] = sys.modules.get(k)

        try:
            modules = install_test_modules()

            # All expected modules are installed
            for k in keys_to_watch:
                assert k in sys.modules
                assert k in modules

            # Ninja stubs are accessible
            ninja_mod = sys.modules["altissimo.auth.ninja"]
            assert hasattr(ninja_mod, "ApiKeyAuth")
            assert hasattr(ninja_mod, "FirebaseAuth")
            assert hasattr(ninja_mod, "LayeredAuth")
            assert hasattr(ninja_mod, "configure")

            # Models are accessible
            models_mod = sys.modules["altissimo.auth.core.models"]
            assert hasattr(models_mod, "APIKeyRecord")
            assert hasattr(models_mod, "FirebaseUser")

            # Telemetry is a no-op
            telemetry_mod = sys.modules["altissimo.auth.core.telemetry"]
            telemetry_mod.log_auth_event(event="test")  # Should not raise

        finally:
            # Restore original modules
            for k in keys_to_watch:
                if saved[k] is not None:
                    sys.modules[k] = saved[k]
                else:
                    sys.modules.pop(k, None)

    def test_custom_api_key_class(self):
        """install_test_modules accepts a custom api_key_auth_class."""
        import sys

        from altissimo.auth.testing import install_test_modules

        class CustomApiKey:
            pass

        saved = {k: sys.modules.get(k) for k in ["altissimo.auth.ninja"]}
        try:
            install_test_modules(api_key_auth_class=CustomApiKey)
            ninja_mod = sys.modules["altissimo.auth.ninja"]
            assert ninja_mod.ApiKeyAuth is CustomApiKey
        finally:
            for k, v in saved.items():
                if v is not None:
                    sys.modules[k] = v
                else:
                    sys.modules.pop(k, None)
