"""Auth Cascade — multi-method fallback for Django Ninja."""

from typing import Any


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

    def __init__(self, auth_methods: list[Any]) -> None:
        """Initialize with a list of callable auth methods."""
        self.auth_methods = auth_methods

    def __call__(self, request: Any) -> Any | None:
        """Try each method in sequence. Return the first non-None result."""
        for method in self.auth_methods:
            result = method(request)
            if result is not None:
                return result
        return None
