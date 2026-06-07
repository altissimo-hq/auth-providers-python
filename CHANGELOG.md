# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2024-01-01

### Added

- Core authentication models (`AuthPrincipal`, `AuthSource`, `AuthReasonCode`, `FirebaseUser`, `GoogleUser`, `GoogleTokenInfo`, `IAPIdentity`, `APIKeyRecord`)
- Core exception hierarchy (`AuthError`, `AuthUnauthorizedError`, `AuthForbiddenError`, `AuthNotFoundError`, `GoogleTokenVerificationError`)
- Authorization policy service (`AuthPolicyService`) with admin checks and custom claim validation
- Structured telemetry logging via `log_auth_event`
- Authentication providers:
  - API Key (pluggable `APIKeyBackend` protocol)
  - Firebase (token verification + user record resolution)
  - Google OAuth2 (ID token verification)
  - Google IAP (header extraction)
  - OIDC (service-to-service with configurable `OIDCPolicy`)
  - Webhooks (pluggable `WebhookVerifier` protocol with Stripe implementation)
- `AuthService` orchestration layer wiring providers and policies
- FastAPI adapter with `Depends()` wrappers and telemetry
- Django Ninja adapter with auth classes
- `py.typed` marker for PEP 561 compliance
- Comprehensive test suite (86 tests, 94% coverage)
