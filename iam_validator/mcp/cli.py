"""Shared argparse layer for both MCP entry points.

No flag here ever carries an auth token -- ``--auth`` only selects a provider by name;
token/JWT/IdP material is env-var- or file-only (see ``auth.py``).
"""

from __future__ import annotations

import argparse
from collections.abc import Mapping
from typing import Any

from iam_validator.mcp.settings import ServerSettings

# Fields ServerSettings.from_env()/ServerSettings resolve directly from CLI flags of the
# same name; --config is the one flag whose dest (config_source) differs from its flag name.
_SETTINGS_FIELDS = (
    "mode",
    "transport",
    "host",
    "port",
    "config_source",
    "auth",
    "profile",
    "custom_checks_dir",
    "aws_services_dir",
    "cache_directory",
    "instructions",
    "instructions_file",
    "allowed_regions",
    "analyze_rate_limit",
    "max_policies",
    "max_policy_bytes",
    "max_request_bytes",
    "request_timeout_s",
    "max_response_bytes",
)


def _transport_type(value: str) -> str:
    if value == "sse":
        raise argparse.ArgumentTypeError(
            "sse was removed: MCP revision 2026-07-28 defines only stdio and Streamable "
            "HTTP as transports (HTTP+SSE was replaced by Streamable HTTP in 2025-03-26 "
            "and has since been dropped from the spec, not merely deprecated). Use "
            "--transport http instead."
        )
    return value


def add_arguments(parser: argparse.ArgumentParser) -> None:
    """Add every ``ServerSettings``-backed flag, plus ``--list-profiles``, to ``parser``.

    Every flag defaults to ``None``, so an unset flag never overrides its env var.
    """
    parser.add_argument(
        "--mode",
        choices=["local", "hosted"],
        default=None,
        help="Server mode (default: local).",
    )
    parser.add_argument(
        "--transport",
        type=_transport_type,
        choices=["stdio", "http"],
        default=None,
        help="Transport protocol (default: stdio).",
    )
    parser.add_argument(
        "--host",
        default=None,
        help="Bind host, used only with --transport http (default: 127.0.0.1; MCP "
        "requires a local-only default, 0.0.0.0 is opt-in).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="Bind port, used only with --transport http (default: 8000).",
    )
    parser.add_argument(
        "--config",
        dest="config_source",
        metavar="FILE",
        default=None,
        help="Path to configuration YAML file to load at startup.",
    )
    parser.add_argument(
        "--auth",
        default=None,
        metavar="PROVIDER",
        help="Auth provider: none, token, jwt, or an IdP name (azure/google/github/"
        "keycloak/auth0/workos). Selects a provider only -- token/JWT/IdP material is "
        "read from IAM_VALIDATOR_MCP_AUTH_* env vars or a file, never a flag.",
    )
    parser.add_argument(
        "--profile",
        choices=["full", "validate-only", "validate-and-query", "read-only"],
        default=None,
        help="Limit which MCP tools are exposed (default: full).",
    )
    parser.add_argument(
        "--list-profiles",
        action="store_true",
        help="Print the profile -> tool taxonomy and exit.",
    )
    parser.add_argument(
        "--custom-checks-dir",
        metavar="DIR",
        default=None,
        help="Directory of Python modules with custom PolicyCheck subclasses to auto-discover.",
    )
    parser.add_argument(
        "--aws-services-dir",
        metavar="DIR",
        default=None,
        help="Directory of pre-downloaded AWS service definitions for offline mode.",
    )
    parser.add_argument(
        "--cache-directory",
        metavar="DIR",
        default=None,
        help="Directory for the AWS service-data disk cache.",
    )
    instructions_group = parser.add_mutually_exclusive_group()
    instructions_group.add_argument(
        "--instructions",
        metavar="TEXT",
        default=None,
        help="Inline custom instructions appended to the default LLM instructions.",
    )
    instructions_group.add_argument(
        "--instructions-file",
        metavar="FILE",
        default=None,
        help="Path to a file (markdown, txt) containing custom instructions.",
    )
    parser.add_argument(
        "--allowed-regions",
        metavar="REGION[,REGION...]",
        default=None,
        help="Comma-separated AWS regions analyze_policy may target (default: the server's own region only).",
    )
    parser.add_argument(
        "--analyze-rate-limit",
        type=int,
        default=None,
        help="Max analyze_policy calls per minute; 0 disables the limit (default: 10).",
    )
    parser.add_argument(
        "--max-policies",
        type=int,
        default=None,
        help="Max policies accepted in one validate_policies call (default: 50).",
    )
    parser.add_argument(
        "--max-policy-bytes",
        type=int,
        default=None,
        help="Max size of a single policy, in bytes (default: 1 MiB).",
    )
    parser.add_argument(
        "--max-request-bytes",
        type=int,
        default=None,
        help="Max total request size, in bytes (default: 8 MiB).",
    )
    parser.add_argument(
        "--request-timeout-s",
        type=int,
        default=None,
        help="Per-request timeout, in seconds (default: 60).",
    )
    parser.add_argument(
        "--max-response-bytes",
        type=int,
        default=None,
        help="Max response size before detail is degraded and the response is marked "
        "truncated, in bytes (default: 4 MiB).",
    )


def resolve_settings(args: argparse.Namespace, *, env: Mapping[str, str] | None = None) -> ServerSettings:
    """Merge parsed flags from ``args`` over ``IAM_VALIDATOR_MCP_*`` env vars.

    Precedence is flags > env vars > defaults. Both layers must be validated in one
    ``ServerSettings`` call: cross-field validators may only see the merged result.
    """
    merged = ServerSettings._env_kwargs(env)
    overrides: dict[str, Any] = {
        field: value for field in _SETTINGS_FIELDS if (value := getattr(args, field, None)) is not None
    }
    if args.auth is not None:
        overrides["auth_explicitly_set"] = True
    merged.update(overrides)
    return ServerSettings(**merged)


def run_kwargs(settings: ServerSettings) -> dict[str, Any]:
    """``FastMCP.run()``/``run_async()`` transport kwargs for ``settings``.

    ``run_stdio_async`` has no ``host``/``port`` parameters, so these must only be
    passed for the http transport.
    """
    if settings.transport == "http":
        return {"host": settings.host, "port": settings.port}
    return {}


__all__ = ["add_arguments", "resolve_settings", "run_kwargs"]
