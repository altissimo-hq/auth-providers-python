"""Tests for the webhook provider."""

from __future__ import annotations

from typing import Any

import pytest

from altissimo.auth.core.exceptions import AuthUnauthorizedError
from altissimo.auth.core.models import AuthReasonCode
from altissimo.auth.providers.webhooks import WebhookProvider, WebhookVerifier


class FakeVerifier:
    """Test verifier that returns the payload as-is."""

    def verify(self, payload: str | bytes, signature: str) -> Any:
        if signature == "bad":
            raise AuthUnauthorizedError("Bad signature", reason_code=AuthReasonCode.INVALID_WEBHOOK_SIGNATURE)
        return {"payload": payload, "verified": True}


class TestWebhookProvider:
    def test_verify_delegates(self) -> None:
        provider = WebhookProvider(FakeVerifier())
        result = provider.verify('{"event": "test"}', "good-sig")
        assert result["verified"] is True

    def test_verify_propagates_error(self) -> None:
        provider = WebhookProvider(FakeVerifier())
        with pytest.raises(AuthUnauthorizedError) as exc:
            provider.verify("payload", "bad")
        assert exc.value.reason_code == AuthReasonCode.INVALID_WEBHOOK_SIGNATURE


class TestWebhookVerifierProtocol:
    def test_fake_satisfies_protocol(self) -> None:
        assert isinstance(FakeVerifier(), WebhookVerifier)
