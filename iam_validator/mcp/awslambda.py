"""AWS Lambda entry point: wraps the production ASGI app (``mcp/asgi.py``) via Mangum.

``json_response=True`` is required here, not optional: the Python managed Lambda
runtime has no response-streaming mode, and API Gateway buffers the response body
regardless of what the app sends, so ``text/event-stream`` never reaches the caller
usably. This constrains what a tool may do under this handler to a single request/
response -- no progress notification, no logging notification, no sampling request
(``tests/mcp/test_json_response.py`` asserts this). ``GET /mcp`` (the SSE-only
optional channel) answers 405, which is conformant: it was never required.

Filesystem: ``/tmp`` is the only writable path in the Lambda execution environment.
``IAM_VALIDATOR_MCP_CACHE_DIRECTORY`` must point under ``/tmp`` here -- and note this
is a within-environment optimization only, not a cache guarantee: a cold-started
(recycled) environment starts with an empty ``/tmp``, so cache misses on service data
are expected, not a bug. AWS service data is fetched lazily per service
(``aws_service/fetcher.py``), so this only affects per-request latency, never
init/cold-start time.

Cold start: Mangum runs the ASGI ``lifespan`` on the first invocation an environment
handles (``lifespan="on"``), so that cost lands on a request, not on init. AWS
SnapStart is deliberately NOT enabled for this function: a restored snapshot would
resurrect a cached JWKS set, a live httpx connection pool, and any seeded RNG state,
none of which should survive a snapshot restore. Adopting SnapStart safely needs
restore hooks that reset all three; that's future work, not done here.

``request_timeout_s`` (``ServerSettings``, default 60s, enforced via
``asyncio.wait_for`` in ``tools/validate.py``) must be set below the Lambda
function's own configured timeout -- a deployment concern, not something this
module can enforce. An HTTP API Gateway integration additionally hard-caps at 30s
regardless of the function's timeout; prefer a Lambda Function URL as the front end
(no such cap) and reserve API Gateway for cases that need its authorizers or usage
plans.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from mangum import Mangum

from iam_validator.mcp.asgi import create_app
from iam_validator.mcp.auth import AWS_GATEWAY_AUTH_PROVIDER
from iam_validator.mcp.settings import ServerSettings

logger = logging.getLogger(__name__)


def _check_function_url_auth_type() -> None:
    """Refuse to start if this function also exposes a Function URL with ``AuthType: NONE``.

    A ``--auth aws-gateway`` deployment trusts ``requestContext.authorizer`` entirely;
    an anonymous ``AuthType: NONE`` Function URL would let a caller reach the adapter
    with no authorizer block at all, which the auth backend already treats as
    unauthenticated -- but that's a silent downgrade to no-auth, not a startup
    failure, unless this check catches it first. Best-effort: when the check itself
    can't be made (no function name, no permissions, no boto3, network failure), this
    logs a warning and starts anyway -- verifying the Function URL's AuthType is then
    the operator's responsibility.
    """
    function_name = os.environ.get("AWS_LAMBDA_FUNCTION_NAME")
    if not function_name:
        logger.warning(
            "AWS_LAMBDA_FUNCTION_NAME is not set; skipping the Function URL AuthType=NONE "
            "self-check. Verify manually that no Function URL for this function has "
            "AuthType=NONE while --auth aws-gateway is in use."
        )
        return

    try:
        import boto3

        client = boto3.client("lambda")
        config = client.get_function_url_config(FunctionName=function_name)
    except Exception as exc:  # noqa: BLE001 -- any failure here is "can't verify", not "verified safe"
        response = getattr(exc, "response", None)
        error_code = response.get("Error", {}).get("Code") if isinstance(response, dict) else None
        if error_code == "ResourceNotFoundException":
            return  # No Function URL configured; nothing to check.
        logger.warning(
            "Could not verify this function's Function URL AuthType (%s: %s); starting anyway. "
            "Verify manually that AuthType != NONE while --auth aws-gateway is in use.",
            type(exc).__name__,
            exc,
        )
        return

    if config.get("AuthType") == "NONE":
        raise SystemExit(
            "iam-validator-mcp: refusing to start with --auth aws-gateway: this function's "
            "Function URL has AuthType=NONE, which would let an unauthenticated caller reach "
            "the adapter directly. Set AuthType=AWS_IAM, or front this function with an "
            "authenticated API Gateway route instead."
        )


class _SatisfyBearerPresenceGate:
    """Adds a placeholder ``Authorization`` header when the request has none.

    FastMCP's ``RequireAuthMiddleware`` (``fastmcp/server/auth/middleware.py``) 401s
    any request lacking an ``Authorization`` header before it ever looks at
    ``scope["user"]`` -- a global RFC 6750 Section 3.1 gate that sits in front of
    ``AwsGatewayAuthProvider``'s own middleware (``auth.py:_AwsGatewayBackend``), which
    authenticates from ``scope["aws.event"].requestContext`` and never reads a header.
    Without this, that gate would 401 every aws-gateway request, including a
    legitimately authorized one, before the backend runs at all.

    Only wrapped in when ``settings.auth == "aws-gateway"``, and only fills a header
    that is already absent -- it never overwrites one a caller sent. The value is a
    fixed, non-secret sentinel: nothing ever reads it back for identity or scope,
    which still come solely from ``requestContext`` per ``_AwsGatewayBackend``.
    """

    def __init__(self, app: Any) -> None:
        self._app = app

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] == "http" and not any(k.lower() == b"authorization" for k, _v in scope.get("headers", [])):
            scope = {**scope, "headers": [*scope.get("headers", []), (b"authorization", b"Bearer aws-gateway")]}
        await self._app(scope, receive, send)


def create_handler(settings: ServerSettings | None = None) -> Mangum:
    """Build the Mangum handler. ``settings`` defaults to ``ServerSettings.from_env()``.

    There is no command line under Lambda, so this always resolves configuration
    from the environment (mirrors ``ServerSettings.from_env()``'s own docstring).
    """
    if settings is None:
        settings = ServerSettings.from_env()

    app: Any = create_app(settings, json_response=True, allow_aws_gateway=True)

    if settings.auth == AWS_GATEWAY_AUTH_PROVIDER:
        _check_function_url_auth_type()
        app = _SatisfyBearerPresenceGate(app)

    return Mangum(app, lifespan="on")


def __getattr__(name: str) -> Any:
    """Lazily build the module-level ``handler`` (PEP 562).

    Keeps ``import iam_validator.mcp.awslambda`` side-effect-free for tests; only
    attribute access -- ``iam_validator.mcp.awslambda.handler``, which is both
    ``from ... import handler`` and how the AWS Lambda runtime resolves a handler
    string -- triggers construction.
    """
    if name == "handler":
        return create_handler()
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = ["create_handler", "handler"]  # noqa: F822 -- "handler" is served by __getattr__ above
