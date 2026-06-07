# Contributing to altissimo-auth

Thank you for considering contributing to `altissimo-auth`! This guide will help you get started.

## Development Setup

### Prerequisites

- Python 3.11+
- [Poetry 2.0+](https://python-poetry.org/docs/#installation)

### Getting Started

```bash
# Clone the repository
git clone https://github.com/altissimo-hq/auth-providers-python.git
cd auth-providers-python

# Install all dependencies (including dev and all optional extras)
poetry sync

# Install pre-commit hooks
poetry run pre-commit install

# Verify everything works
poetry run pytest
poetry run ruff check .
poetry run ruff format --check .
```

## Development Workflow

### Running Tests

```bash
# Run all tests
poetry run pytest

# Run with coverage
poetry run pytest --cov=altissimo --cov-report=term-missing

# Run a specific test file
poetry run pytest tests/test_models.py

# Run a specific test
poetry run pytest tests/test_models.py::TestGoogleUser::test_email_lowercased
```

### Linting & Formatting

```bash
# Check for lint errors
poetry run ruff check .

# Auto-fix lint errors
poetry run ruff check --fix .

# Check formatting
poetry run ruff format --check .

# Auto-format
poetry run ruff format .
```

### Pre-commit Hooks

Pre-commit hooks run automatically on `git commit`. To run them manually:

```bash
poetry run pre-commit run --all-files
```

## Code Standards

- **Type hints**: All public APIs must have complete type annotations
- **Docstrings**: All public classes and methods must have docstrings
- **Tests**: All new features must include tests; aim for >90% coverage
- **Linting**: Code must pass `ruff check` and `ruff format` with the project's configuration

## Architecture

```text
altissimo.auth
├── core/           # Framework-agnostic models, exceptions, policies
├── providers/      # Token/key verification (stateless, no framework deps)
├── service.py      # AuthService orchestration layer
├── fastapi/        # FastAPI Depends() wrappers
└── ninja/          # Django Ninja auth classes
```

### Key Principles

1. **Providers** are framework-agnostic and contain the actual auth logic
2. **AuthService** wires providers + policies together
3. **Adapters** (FastAPI, Ninja) are thin wrappers that delegate to AuthService
4. **Protocols** (e.g., `APIKeyBackend`, `WebhookVerifier`) allow pluggable backends

### Adding a New Provider

1. Create `src/altissimo/auth/providers/your_provider.py`
2. Add methods to `AuthService` in `service.py`
3. Add adapter methods in `fastapi/__init__.py` and/or `ninja/__init__.py`
4. Add tests in `tests/providers/test_your_provider.py`
5. Export from `providers/__init__.py`

## Submitting Changes

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Make your changes with tests
4. Ensure all checks pass (`poetry run pytest && poetry run ruff check .`)
5. Commit with a descriptive message
6. Push to your fork and open a Pull Request

## License

By contributing, you agree that your contributions will be licensed under the [Apache License 2.0](LICENSE).
