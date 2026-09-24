"""Structured per-hosted-tool-call audit logging.

``audited_call`` emits one JSON record per call on the ``iam_validator.mcp.audit``
logger; a no-op outside hosted mode.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone
from typing import Any

from fastmcp.exceptions import ToolError

from iam_validator.core.constants import (
    MCP_AUDIT_LOGGER_NAME,
    MCP_AUDIT_OUTCOME_CANCELLED,
    MCP_AUDIT_OUTCOME_INTERNAL_ERROR,
    MCP_AUDIT_OUTCOME_SUCCESS,
    MCP_AUDIT_OUTCOME_TOOL_ERROR,
)
from iam_validator.mcp.context import get_server_context

logger = logging.getLogger(MCP_AUDIT_LOGGER_NAME)


def _subject_and_scopes() -> tuple[str, list[str]]:
    """``(subject, scopes)`` off the verified access token, or anonymous under ``--auth none``."""
    from fastmcp.server.dependencies import get_access_token

    token = get_access_token()
    if token is None:
        return "anonymous", []
    return token.subject or token.client_id or "anonymous", sorted(token.scopes)


def _severity_counts(response: dict[str, Any] | None) -> dict[str, int]:
    """Sum each result entry's ``severity_counts``. Pre-aggregated integers only -- never a message."""
    totals: dict[str, int] = {}
    if not response:
        return totals
    for entry in response.get("results", ()) or ():
        if not isinstance(entry, dict):
            continue
        counts = entry.get("severity_counts")
        if not isinstance(counts, dict):
            continue
        for severity, count in counts.items():
            if isinstance(count, int):
                totals[severity] = totals.get(severity, 0) + count
    return totals


async def audited_call(
    tool_name: str,
    ctx: Any,
    policy_count: int,
    call: Callable[[], Awaitable[dict[str, Any]]],
) -> dict[str, Any]:
    """Run ``call()``, emitting exactly one audit record before returning or raising.

    A no-op wrapper outside hosted mode (no ``ServerContext``, or
    ``settings.mode != "hosted"``): just awaits and returns ``call()``, so
    local stdio mode never emits a record.

    A failure while building or emitting the record is logged separately at
    warning level and never propagates -- the audit path must not be able to
    fail the tool call it observes.

    Raises:
        ToolError: propagated from ``call()``; the record's ``outcome`` is
            ``tool_error``.
        asyncio.CancelledError: propagated from ``call()``; the record's
            ``outcome`` is ``cancelled``.
        Exception: any other error from ``call()`` is propagated after the
            record is logged with ``outcome`` ``internal_error`` (FastMCP
            masks its details from the caller; the audit log is the only
            place the failure is attributed to a subject/tool/time).
    """
    context = get_server_context(ctx)
    if context is None or context.settings.mode != "hosted":
        return await call()

    subject, scopes = _subject_and_scopes()
    start = time.monotonic()
    outcome = MCP_AUDIT_OUTCOME_SUCCESS
    response: dict[str, Any] | None = None
    try:
        response = await call()
        return response
    except ToolError:
        outcome = MCP_AUDIT_OUTCOME_TOOL_ERROR
        raise
    except asyncio.CancelledError:
        outcome = MCP_AUDIT_OUTCOME_CANCELLED
        raise
    except Exception:
        outcome = MCP_AUDIT_OUTCOME_INTERNAL_ERROR
        raise
    finally:
        try:
            record = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "tool": tool_name,
                "subject": subject,
                "scopes": scopes,
                "config_digest": context.config_digest,
                "policy_count": policy_count,
                "duration_s": round(time.monotonic() - start, 6),
                "outcome": outcome,
                "severity_counts": _severity_counts(response),
            }
            logger.info(json.dumps(record, sort_keys=True))
        except Exception:
            logger.warning("failed to emit audit record for tool %s", tool_name, exc_info=True)


__all__ = ["audited_call"]
