"""Tests for the OIDC service account provider."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from altissimo.auth.core.exceptions import AuthForbiddenError, AuthUnauthorizedError
from altissimo.auth.core.models import AuthReasonCode
from altissimo.auth.providers.oidc import OIDCPolicy, OIDCProvider

_POLICY = OIDCPolicy(
    allowed_callers={
        "dev": ["sa-dev@project-dev.iam.gserviceaccount.com"],
        "prod": ["sa-prod@project-prod.iam.gserviceaccount.com"],
    },
    valid_audiences={
        "dev": ["https://api-dev.run.app", "https://api.dev.example.com"],
        "prod": ["https://api-prod.run.app"],
    },
    project_sa_suffix="@project-{env}.iam.gserviceaccount.com",
    team_domains=["example.com"],
)


class TestIsAuthorizedCaller:
    def _check(self, email: str, env: str, policy: OIDCPolicy = _POLICY) -> bool:
        return OIDCProvider._is_authorized_caller(email, env, policy)

    def test_explicit_caller_allowed(self) -> None:
        assert self._check("sa-dev@project-dev.iam.gserviceaccount.com", "dev") is True

    def test_explicit_caller_wrong_env(self) -> None:
        assert self._check("sa-dev@project-dev.iam.gserviceaccount.com", "prod") is False

    def test_project_sa_allowed(self) -> None:
        assert self._check("worker@project-dev.iam.gserviceaccount.com", "dev") is True

    def test_project_sa_wrong_env(self) -> None:
        assert self._check("worker@project-dev.iam.gserviceaccount.com", "prod") is False

    def test_team_domain_allowed_in_nonprod(self) -> None:
        assert self._check("dev@example.com", "dev") is True

    def test_team_domain_blocked_in_prod(self) -> None:
        assert self._check("dev@example.com", "prod") is False

    def test_unknown_blocked(self) -> None:
        assert self._check("evil@attacker.com", "dev") is False

    def test_empty_email_blocked(self) -> None:
        assert self._check("", "dev") is False

    def test_team_blocked_when_flag_off(self) -> None:
        policy = OIDCPolicy(
            allowed_callers=_POLICY.allowed_callers,
            valid_audiences=_POLICY.valid_audiences,
            allow_team_in_nonprod=False,
        )
        assert self._check("dev@example.com", "dev", policy) is False

    def test_project_sa_blocked_when_no_suffix(self) -> None:
        policy = OIDCPolicy(
            allowed_callers=_POLICY.allowed_callers,
            valid_audiences=_POLICY.valid_audiences,
            project_sa_suffix=None,
        )
        assert self._check("worker@project-dev.iam.gserviceaccount.com", "dev", policy) is False


class TestVerifyToken:
    @patch("altissimo.auth.providers.oidc.google.oauth2.id_token.verify_oauth2_token")
    @patch("altissimo.auth.providers.oidc.google.auth.transport.requests.Request")
    def test_success(self, mock_request: MagicMock, mock_verify: MagicMock) -> None:
        mock_verify.return_value = {"email": "sa-dev@project-dev.iam.gserviceaccount.com"}

        result = OIDCProvider.verify_token("token", "dev", _POLICY)

        assert result == "sa-dev@project-dev.iam.gserviceaccount.com"

    @patch("altissimo.auth.providers.oidc.google.oauth2.id_token.verify_oauth2_token")
    @patch("altissimo.auth.providers.oidc.google.auth.transport.requests.Request")
    def test_tries_second_audience(self, mock_request: MagicMock, mock_verify: MagicMock) -> None:
        call_count = 0

        def _side_effect(token, request, audience=None):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise ValueError("wrong audience")
            return {"email": "sa-dev@project-dev.iam.gserviceaccount.com"}

        mock_verify.side_effect = _side_effect

        result = OIDCProvider.verify_token("token", "dev", _POLICY)
        assert result == "sa-dev@project-dev.iam.gserviceaccount.com"
        assert call_count == 2

    @patch("altissimo.auth.providers.oidc.google.oauth2.id_token.verify_oauth2_token")
    @patch("altissimo.auth.providers.oidc.google.auth.transport.requests.Request")
    def test_all_audiences_fail(self, mock_request: MagicMock, mock_verify: MagicMock) -> None:
        mock_verify.side_effect = ValueError("bad")

        with pytest.raises(AuthUnauthorizedError) as exc:
            OIDCProvider.verify_token("token", "dev", _POLICY)
        assert exc.value.reason_code == AuthReasonCode.INVALID_OIDC_TOKEN

    @patch("altissimo.auth.providers.oidc.google.oauth2.id_token.verify_oauth2_token")
    @patch("altissimo.auth.providers.oidc.google.auth.transport.requests.Request")
    def test_transport_error(self, mock_request: MagicMock, mock_verify: MagicMock) -> None:
        import google.auth.exceptions

        mock_verify.side_effect = google.auth.exceptions.TransportError("network")

        with pytest.raises(AuthUnauthorizedError) as exc:
            OIDCProvider.verify_token("token", "dev", _POLICY)
        assert exc.value.reason_code == AuthReasonCode.AUTH_SERVICE_UNAVAILABLE

    @patch("altissimo.auth.providers.oidc.google.oauth2.id_token.verify_oauth2_token")
    @patch("altissimo.auth.providers.oidc.google.auth.transport.requests.Request")
    def test_unauthorized_caller(self, mock_request: MagicMock, mock_verify: MagicMock) -> None:
        mock_verify.return_value = {"email": "evil@attacker.com"}

        with pytest.raises(AuthForbiddenError) as exc:
            OIDCProvider.verify_token("token", "dev", _POLICY)
        assert exc.value.reason_code == AuthReasonCode.UNAUTHORIZED_CALLER

    def test_no_audiences_for_env(self) -> None:
        with pytest.raises(AuthUnauthorizedError) as exc:
            OIDCProvider.verify_token("token", "unknown-env", _POLICY)
        assert exc.value.reason_code == AuthReasonCode.INVALID_OIDC_TOKEN
