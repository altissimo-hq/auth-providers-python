"""Structured auth event logging.

Provides a single `log_auth_event` helper that emits structured JSON log
entries.  Consumers can replace the logger or add handlers as needed.
"""

from __future__ import annotations

import logging

from .models import AuthReasonCode

logger = logging.getLogger("altissimo.auth")


def log_auth_event(
    *,
    event: str,
    auth_source: str,
    route: str,
    method: str,
    status_code: int,
    reason_code: AuthReasonCode | str,
    principal_id: str | None = None,
) -> None:
    """Emit a structured auth log event."""
    normalized = reason_code.value if isinstance(reason_code, AuthReasonCode) else reason_code
    logger.info(
        "auth event: %s",
        event,
        extra={
            "json_fields": {
                "event": event,
                "auth_source": auth_source,
                "route": route,
                "method": method,
                "status_code": status_code,
                "reason_code": normalized,
                "principal_id": principal_id,
            }
        },
    )
