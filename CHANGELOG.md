# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `LayeredAuth` class in Django Ninja adapter for required gate + optional identity auth pattern (BFF endpoints). Composes a required auth gate (e.g. `ApiKeyAuth`) with an optional identity enrichment (e.g. `FirebaseAuth`). Stashes gate result on `request.gate_auth` and merges OpenAPI security schemes. ([#9](https://github.com/altissimo-hq/auth-providers-python/issues/9))
- `IdentityAuth` protocol for `LayeredAuth` identity parameter — loosens type from `NinjaHttpBearer` to a `Protocol`, enabling custom identity providers (cookies, device tokens, etc.) alongside built-in bearer auth classes. ([#10](https://github.com/altissimo-hq/auth-providers-python/issues/10))

### Fixed

- `LayeredAuth` now uses `request.headers` instead of `request.META` for the Authorization header lookup, fixing compatibility with Django Ninja's `TestClient` which preserves mixed-case META keys. ([#11](https://github.com/altissimo-hq/auth-providers-python/issues/11))

## [1.0.0] - 2026-06-07

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
- Flask adapter with `OAuth2FlowManager` for Google Server-Side OAuth2
- `AuthCascade` for multi-method fallback auth patterns
- `py.typed` marker for PEP 561 compliance
- Comprehensive test suite (86 tests, 94% coverage)
