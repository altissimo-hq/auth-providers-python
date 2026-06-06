"""API key authentication provider.

The provider delegates key lookup to a pluggable :class:`APIKeyBackend`
so that consumers can bring their own storage (Firestore, SQL, Redis, etc.).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from ..core.models import APIKeyRecord


@runtime_checkable
class APIKeyBackend(Protocol):
    """Protocol for API key storage backends.

    Implement this protocol to integrate your own key store.
    """

    def get_key(self, key_id: str) -> APIKeyRecord | None:
        """Look up an API key by its identifier.

        Returns:
            The matching :class:`APIKeyRecord`, or ``None`` if not found.
        """
        ...


class APIKeyProvider:
    """API key lookup provider."""

    def __init__(self, backend: APIKeyBackend) -> None:
        self._backend = backend

    def get_api_key(self, api_key_id: str | None) -> APIKeyRecord | None:
        """Get API key by id or return None."""
        if not api_key_id or not api_key_id.strip():
            return None
        normalized = api_key_id.strip()
        return self._backend.get_key(normalized)
