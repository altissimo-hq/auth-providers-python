"""Google IAP (Identity-Aware Proxy) header extraction.

Extracts user identity from IAP-injected headers.  This provider does
not perform any user/admin lookup — that is the consumer's responsibility.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..core.models import IAPIdentity

if TYPE_CHECKING:
    from collections.abc import Mapping


class IAPProvider:
    """Google IAP header parsing."""

    _GOOGLE_PREFIX = "accounts.google.com:"

    @classmethod
    def parse_header_value(cls, value: str) -> str:
        """Normalize IAP header values by stripping the accounts.google.com prefix."""
        return value.replace(cls._GOOGLE_PREFIX, "").strip().lower()

    @classmethod
    def get_identity(cls, headers: Mapping[str, str]) -> IAPIdentity:
        """Extract IAP identity from request headers.

        Returns:
            An :class:`IAPIdentity` with ``email`` and ``user_id`` extracted
            from the standard IAP headers.
        """
        raw_email = headers.get("X-Goog-Authenticated-User-Email", "")
        raw_id = headers.get("X-Goog-Authenticated-User-Id", "")

        email = cls.parse_header_value(raw_email) or None
        user_id = cls.parse_header_value(raw_id) or None

        return IAPIdentity(email=email, user_id=user_id)
