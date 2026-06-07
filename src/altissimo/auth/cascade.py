"""Auth Cascade — multi-method fallback for Django Ninja."""

import logging
from collections.abc import Callable
from typing import Any

logger = logging.getLogger(__name__)


class AuthCascade:
    """Try multiple auth methods sequentially, returning the first success.

    This is useful for endpoints that accept multiple forms of authentication
    (e.g., Firebase ID token, Google OAuth2 token, or API key) and need to
    return the specific model for whichever method succeeded.

    Usage with Django Ninja:
        cascade = AuthCascade([
            FirebaseAuth(),
            GoogleAuth(),
        ])

        @api.get("/info", auth=cascade)
        def info(request):
            user = request.auth
            ...
    """

    def __init__(self, auth_methods: list[Callable]) -> None:
        """Initialize with a list of callable auth methods."""
        self.auth_methods = auth_methods

    def __call__(self, request: Any) -> Any | None:
        """Try each method in sequence. Return the first non-None result."""
        for method in self.auth_methods:
            try:
                result = method(request)
                if result is not None:
                    return result
            except Exception as e:
                logger.debug("AuthCascade method %s failed: %s", method.__class__.__name__, e)
                continue
        return None
