"""Webhook signature verification.

Provides a pluggable :class:`WebhookVerifier` protocol and a concrete
Stripe implementation.  Additional verifiers (e.g. for Twilio, GitHub)
can be added by implementing the protocol.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from ..core.exceptions import AuthUnauthorizedError
from ..core.models import AuthReasonCode


@runtime_checkable
class WebhookVerifier(Protocol):
    """Protocol for webhook signature verifiers."""

    def verify(self, payload: str | bytes, signature: str) -> Any:
        """Verify a webhook payload against its signature.

        Returns:
            The deserialized event/payload on success.

        Raises:
            AuthUnauthorizedError: Signature or payload is invalid.
        """
        ...


class StripeWebhookVerifier:
    """Stripe webhook signature verifier.

    Requires the ``stripe`` package (not included in any extra — consumers
    install it directly).
    """

    def __init__(self, webhook_secret: str) -> None:
        self._secret = webhook_secret

    def verify(self, payload: str | bytes, signature: str) -> Any:
        """Verify Stripe webhook payload and return the event."""
        import stripe

        try:
            return stripe.Webhook.construct_event(payload, signature, self._secret)
        except ValueError as exc:
            raise AuthUnauthorizedError(
                f"Invalid Stripe payload: {exc}",
                reason_code=AuthReasonCode.INVALID_WEBHOOK_PAYLOAD,
            ) from exc
        except stripe.SignatureVerificationError as exc:
            raise AuthUnauthorizedError(
                f"Invalid Stripe signature: {exc}",
                reason_code=AuthReasonCode.INVALID_WEBHOOK_SIGNATURE,
            ) from exc


class WebhookProvider:
    """Webhook verification provider."""

    def __init__(self, verifier: WebhookVerifier) -> None:
        self._verifier = verifier

    def verify(self, payload: str | bytes, signature: str) -> Any:
        """Delegate to the configured verifier."""
        return self._verifier.verify(payload, signature)
