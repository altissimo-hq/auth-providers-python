"""OIDC service-to-service authentication provider.

Validates Google-signed OIDC identity tokens for service-to-service calls
(e.g. between Cloud Run services).  Caller authorization is governed by
a configurable :class:`OIDCPolicy`.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import google.auth.exceptions
import google.auth.transport.requests
import google.oauth2.id_token

from ..core.exceptions import AuthForbiddenError, AuthUnauthorizedError
from ..core.models import AuthReasonCode


@dataclass(frozen=True)
class OIDCPolicy:
    """Configuration for OIDC service account authentication.

    Attributes:
        allowed_callers:
            env -> list of email addresses that are always permitted.
        valid_audiences:
            env -> list of URL strings accepted as the token's ``aud`` claim.
            Tokens are tried against each audience; the first match wins.
        project_sa_suffix:
            When set, any service account email ending with this suffix
            is automatically allowed.  Use a format like
            ``@myproject-{env}.iam.gserviceaccount.com`` (``{env}`` is
            replaced at runtime).
        team_domains:
            When set and ``allow_team_in_nonprod`` is True, personal
            accounts from these domains are accepted in non-prod envs.
        allow_team_in_nonprod:
            Accept team domain accounts in non-prod environments.
        prod_env_name:
            The name of the production environment (default: ``"prod"``).
    """

    allowed_callers: dict[str, list[str]]
    valid_audiences: dict[str, list[str]]
    project_sa_suffix: str | None = None
    team_domains: list[str] = field(default_factory=list)
    allow_team_in_nonprod: bool = True
    prod_env_name: str = "prod"


class OIDCProvider:
    """Stateless provider that validates Google OIDC identity tokens."""

    @classmethod
    def _is_authorized_caller(
        cls,
        email: str,
        env: str,
        policy: OIDCPolicy,
    ) -> bool:
        """Return True if *email* is authorized in *env*."""
        if email in policy.allowed_callers.get(env, []):
            return True

        if policy.project_sa_suffix:
            suffix = policy.project_sa_suffix.replace("{env}", env)
            if email.endswith(suffix):
                return True

        if policy.allow_team_in_nonprod and env != policy.prod_env_name and policy.team_domains:
            for domain in policy.team_domains:
                if email.endswith(f"@{domain}"):
                    return True

        return False

    @classmethod
    def verify_token(
        cls,
        token: str,
        env: str,
        policy: OIDCPolicy,
    ) -> str:
        """Verify a Google OIDC identity token and return the caller's email.

        Returns:
            The verified caller email address.

        Raises:
            AuthUnauthorizedError: Token invalid, expired, or no audience match.
            AuthForbiddenError: Token valid but caller not authorized.
        """
        valid_audiences = policy.valid_audiences.get(env, [])
        id_info: dict | None = None

        for audience in valid_audiences:
            try:
                id_info = google.oauth2.id_token.verify_oauth2_token(
                    token,
                    google.auth.transport.requests.Request(),
                    audience=audience,
                )
                break
            except google.auth.exceptions.TransportError as exc:
                raise AuthUnauthorizedError(
                    "Auth service unavailable: could not fetch Google public certs",
                    reason_code=AuthReasonCode.AUTH_SERVICE_UNAVAILABLE,
                ) from exc
            except Exception:
                continue

        if id_info is None:
            raise AuthUnauthorizedError(
                "Unauthorized: OIDC token rejected for all configured audiences",
                reason_code=AuthReasonCode.INVALID_OIDC_TOKEN,
            )

        caller_email: str = id_info.get("email", "")
        if not cls._is_authorized_caller(caller_email, env, policy):
            raise AuthForbiddenError(
                f"Forbidden: caller {caller_email!r} is not authorized in env={env!r}",
                reason_code=AuthReasonCode.UNAUTHORIZED_CALLER,
            )

        return caller_email
