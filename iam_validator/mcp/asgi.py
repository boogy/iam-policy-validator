"""ASGI app factory for production (uvicorn) serving; local ``mcp.run()`` stays for ``--transport http``.

``/health``/``/ready`` are top-level routes on the outer app, not ``@mcp.custom_route``s,
so they bypass the mounted FastMCP app's Origin guard and auth middleware.
"""

from __future__ import annotations

import time
from typing import Any

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route

from iam_validator.__version__ import __version__
from iam_validator.mcp.build import build_server
from iam_validator.mcp.context import ServerContext, build_context
from iam_validator.mcp.settings import ServerSettings

_START_TIME = time.monotonic()


def _config_source(context: ServerContext) -> str:
    """Config source kind, never the path -- /health and /ready are unauthenticated."""
    return "file" if context.settings.config_source else "none"


def _base_payload(context: ServerContext) -> dict[str, Any]:
    return {
        "version": __version__,
        "config_digest": context.config_digest,
        "config_source": _config_source(context),
    }


async def _health(request: Request) -> JSONResponse:
    """Liveness: the process is up and can serve a response. Never checks readiness."""
    context: ServerContext = request.app.state.iam_context
    return JSONResponse(
        {"status": "ok", "uptime_s": round(time.monotonic() - _START_TIME, 1), **_base_payload(context)}
    )


async def _ready(request: Request) -> JSONResponse:
    """Readiness: config resolved, registry built, AWS service data available."""
    context: ServerContext = request.app.state.iam_context
    checks = {
        "config_resolved": context.config is not None,
        "registry_built": context.registry is not None,
        "aws_data_ready": context.ready,
    }
    ready = all(checks.values())
    payload = {"status": "ready" if ready else "not_ready", "checks": checks, **_base_payload(context)}
    return JSONResponse(payload, status_code=200 if ready else 503)


def create_app(
    settings: ServerSettings | None = None,
    *,
    json_response: bool = False,
    allow_aws_gateway: bool = False,
) -> Starlette:
    """Build the production ASGI app: FastMCP mounted under liveness/readiness routes.

    ``settings`` defaults to ``ServerSettings.from_env()``. ``json_response`` and
    ``allow_aws_gateway`` exist so ``iam_validator.mcp.awslambda`` can reuse this
    factory (keeping ``/health``/``/ready`` registered, if unused, under Lambda)
    instead of duplicating the app construction; every other caller leaves both
    at their default.
    """
    if settings is None:
        settings = ServerSettings.from_env()

    context = build_context(settings)
    mcp = build_server(settings, context=context, allow_aws_gateway=allow_aws_gateway)
    mcp_app = mcp.http_app(stateless_http=True, json_response=json_response, host_origin_protection="auto")

    app = Starlette(
        routes=[
            Route("/health", _health, methods=["GET"]),
            Route("/ready", _ready, methods=["GET"]),
            Mount("/", app=mcp_app),
        ],
        lifespan=mcp_app.lifespan,
    )
    app.state.iam_context = context
    return app


__all__ = ["create_app"]
