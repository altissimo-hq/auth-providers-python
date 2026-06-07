# altissimo-auth

[![CI](https://github.com/altissimo-hq/auth-providers-python/actions/workflows/ci.yml/badge.svg)](https://github.com/altissimo-hq/auth-providers-python/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue)](https://www.python.org)
[![License](https://img.shields.io/badge/license-Apache%202.0-green)](LICENSE)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)

Reusable, framework-agnostic authentication library for Python applications.

## Features

- 🔑 **API Key** authentication with pluggable storage backends
- 🔥 **Firebase** ID token verification and user record resolution
- 🌐 **Google OAuth2** ID token verification
- 🛡️ **Google IAP** header extraction
- 🔒 **OIDC** service-to-service authentication with configurable caller policies
- 🪝 **Webhook** signature verification (Stripe included, extensible via protocol)
- ⚡ **FastAPI** adapter with `Depends()` wrappers and structured telemetry
- 🥷 **Django Ninja** adapter with native auth classes
- 🧪 **Flask** adapter for server-side Google OAuth2 Authorization Code flow
- 🌊 **Auth Cascade** for multi-method authentication fallback
- 📐 **Typed** — full type annotations with `py.typed` PEP 561 marker

## Requirements

- Python 3.11+

## Installation

```bash
pip install altissimo-auth[fastapi]        # core + FastAPI adapter
pip install altissimo-auth[ninja]          # core + Django Ninja adapter
pip install altissimo-auth[flask]          # core + Flask OAuth2 adapter
pip install altissimo-auth[firebase]       # core + Firebase provider
pip install altissimo-auth[google]         # core + Google OAuth2/OIDC providers
pip install altissimo-auth[all]            # everything
```

## Quick Start

### FastAPI

```python
from typing import Annotated

from fastapi import Depends, FastAPI

from altissimo.auth import FirebaseUser
from altissimo.auth.fastapi import Auth, configure
from altissimo.auth.service import AuthService

app = FastAPI()

# Configure once at startup
configure(AuthService(api_key_backend=my_backend))

# Route-level guard
@app.get("/items", dependencies=[Depends(Auth.validate_api_key)])
async def list_items():
    ...

# Parameter injection
@app.get("/me")
async def get_me(
    user: Annotated[FirebaseUser, Depends(Auth.validate_firebase_user)],
):
    return {"uid": user.uid, "email": user.email}
```

### Django Ninja

```python
from ninja import NinjaAPI

from altissimo.auth.cascade import AuthCascade
from altissimo.auth.ninja import ApiKeyAuth, FirebaseAuth, OIDCAuth, configure
from altissimo.auth.service import AuthService

api = NinjaAPI()

# Configure once at startup
configure(AuthService(api_key_backend=my_backend))

# Route-level guard
@api.get("/items", auth=ApiKeyAuth())
def list_items(request):
    ...

# Cascading Auth (Multi-Method Fallback)
cascade = AuthCascade([FirebaseAuth(), ApiKeyAuth()])

@api.get("/me", auth=cascade)
def get_me(request):
    user = request.auth  # Will be FirebaseUser or APIKeyRecord
    ...
```

### Flask (Server-Side Google OAuth2)

```python
from flask import Flask, g
from altissimo.auth.flask import OAuth2FlowManager

app = Flask(__name__)
app.secret_key = "super-secret"

auth = OAuth2FlowManager(
    client_secrets_file="client_secret.json",
    scopes=["openid", "email", "profile"],
    redirect_uri_endpoint="oauth2_callback",
    hosted_domain="mycompany.com"  # Optional: restrict to domain
)

@app.route("/login")
def login():
    return auth.login_redirect()

@app.route("/oauth2_callback")
def oauth2_callback():
    user_info = auth.handle_callback()
    return f"Logged in as {user_info['email']}"

@app.route("/logout")
def logout():
    auth.logout()
    return "Logged out"

@app.route("/protected")
@auth.require_auth
def protected():
    return f"Hello, {g.user.email}"  # g.user is populated by require_auth
```

### OIDC Service-to-Service

```python
from altissimo.auth.fastapi import Auth
from altissimo.auth.providers.oidc import OIDCPolicy

policy = OIDCPolicy(
    allowed_callers={
        "dev": ["sa@my-project-dev.iam.gserviceaccount.com"],
        "prod": ["sa@my-project-prod.iam.gserviceaccount.com"],
    },
    valid_audiences={
        "dev": ["https://api-dev.run.app"],
        "prod": ["https://api-prod.run.app"],
    },
    project_sa_suffix="@my-project-{env}.iam.gserviceaccount.com",
    team_domains=["mycompany.com"],
)

verify_caller = Auth.create_oidc_dependency(policy)

@app.post("/callback", dependencies=[Depends(verify_caller)])
async def handle_callback():
    ...
```

## Architecture

```text
altissimo.auth
├── core/           # Framework-agnostic models, exceptions, policies
├── providers/      # Token/key verification (API key, Firebase, Google, OIDC, IAP, webhooks)
├── service.py      # AuthService orchestration layer
├── fastapi/        # FastAPI Depends() wrappers
└── ninja/          # Django Ninja auth classes
```

### Provider → Service → Adapter Pattern

- **Providers** contain the actual auth logic (token verification, key lookup)
- **AuthService** wires providers + policies together
- **Adapters** are thin framework-specific wrappers that delegate to AuthService

### Pluggable Backends

API key storage and webhook verification are abstracted via Python Protocols:

```python
from altissimo.auth.providers import APIKeyBackend

class MyKeyBackend:
    """Implement the APIKeyBackend protocol with your storage."""

    def get_key(self, key_id: str) -> APIKeyRecord | None:
        return db.query(APIKey).filter_by(id=key_id).first()
```

## Development

```bash
# Install all dependencies
poetry sync

# Run tests
poetry run pytest

# Run tests with coverage
poetry run pytest --cov=altissimo --cov-report=term-missing

# Run linters
poetry run ruff check .
poetry run ruff format --check .
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed development guidelines.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history.

## Security

For reporting security vulnerabilities, see [SECURITY.md](SECURITY.md).

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.
