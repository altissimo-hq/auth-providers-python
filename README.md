# altissimo-auth

Reusable, framework-agnostic authentication library for Altissimo projects.

## Installation

```bash
pip install altissimo-auth[fastapi]        # core + FastAPI adapter
pip install altissimo-auth[ninja]          # core + Django Ninja adapter
pip install altissimo-auth[firebase]       # core + Firebase provider
pip install altissimo-auth[google]         # core + Google OAuth2/OIDC providers
pip install altissimo-auth[all]            # everything
```

## Quick Start

### FastAPI

```python
from typing import Annotated

from fastapi import Depends, FastAPI

from altissimo.auth.core.models import FirebaseUser
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

from altissimo.auth.ninja import ApiKeyAuth, FirebaseAuth, OIDCAuth, configure
from altissimo.auth.service import AuthService

api = NinjaAPI()

# Configure once at startup
configure(AuthService(api_key_backend=my_backend))

# Route-level guard
@api.get("/items", auth=ApiKeyAuth())
def list_items(request):
    ...

# Multiple auth methods (OR logic)
@api.get("/me", auth=[FirebaseAuth(), ApiKeyAuth()])
def get_me(request):
    ...
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

## Development

```bash
# Install all dependencies
poetry sync

# Run tests
poetry run pytest

# Run linters
poetry run ruff check .
poetry run ruff format --check .
```

## License

GPL-3.0-or-later
