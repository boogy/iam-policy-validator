"""Server-wide MCP settings, resolved once and read everywhere else.

``ServerSettings`` is the single place server configuration is resolved. Context
construction, the FastMCP app builder, auth provider selection, the CLI entry point,
and the Lambda handler all read a ``ServerSettings`` instance instead of re-deriving
configuration from ``sys.argv`` or ``os.environ`` themselves.

Resolution order: flags -> ``IAM_VALIDATOR_MCP_*`` environment variables -> defaults.
The argparse layer that produces the flag layer lives in the CLI entry point; it
should call :meth:`ServerSettings.from_env` and override the result with explicit
flag values before use. :meth:`ServerSettings.from_env` reads only the environment
(plus defaults) because the Lambda handler constructs the server with no command
line to parse.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

# Numeric limit defaults. Nothing outside this module needs them yet; if a future
# task (e.g. TASK-08 enforcement) needs to share one, move it to
# iam_validator/core/constants.py instead of duplicating it.
DEFAULT_PORT = 8000
DEFAULT_ANALYZE_RATE_LIMIT = 10
DEFAULT_MAX_POLICIES = 50
DEFAULT_MAX_POLICY_BYTES = 1_048_576  # 1 MiB
DEFAULT_MAX_REQUEST_BYTES = 8_388_608  # 8 MiB
DEFAULT_REQUEST_TIMEOUT_S = 60
DEFAULT_MAX_RESPONSE_BYTES = 4_194_304  # 4 MiB
DEFAULT_HTTP_MAX_CONNECTIONS = 50
DEFAULT_HTTP_MAX_KEEPALIVE_CONNECTIONS = 20

_ENV_PREFIX = "IAM_VALIDATOR_MCP_"
# Pre-existing names fixed by the spec that don't follow the FIELD_UPPER convention.
_ENV_VAR_OVERRIDES: dict[str, str] = {
    "config_source": "IAM_VALIDATOR_MCP_CONFIG",
}
# Fields that are never read directly from their own env var; from_env() derives them.
_ENV_DERIVED_FIELDS = frozenset({"auth_explicitly_set"})

# `pathlib.Path` collapses "//" to "/" at construction, so `config_source=Path("https://x")`
# already reads back as "https:/x" with no "://" substring left to find, and pathlib gives no
# way to tell that collapsed URL apart from a genuine colon-bearing filesystem path. Given
# that ambiguity, any two-or-more-character scheme prefix is rejected rather than allowlisted
# by scheme name: a security tool with a "no remote config" invariant should err toward
# rejecting a path an operator can immediately fix, not toward silently accepting a URL.
# The two-character minimum is what keeps a single-letter Windows drive ("C:/x") passing.
_URL_SCHEME_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]+:/", re.IGNORECASE)


def _default_allowed_regions() -> frozenset[str]:
    """Server's own AWS region, if determinable, else unrestricted (empty)."""
    region = os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")
    if not region:
        try:
            import boto3

            region = boto3.Session().region_name
        except Exception:
            region = None
    return frozenset({region}) if region else frozenset()


class ServerSettings(BaseModel):
    """Resolved MCP server configuration.

    Construct directly from explicit (flag) values, or via :meth:`from_env` for
    environment-only resolution.
    """

    model_config = ConfigDict(extra="forbid")

    mode: Literal["local", "hosted"] = "local"
    transport: Literal["stdio", "http"] = "stdio"
    host: str = "127.0.0.1"
    port: int = DEFAULT_PORT
    config_source: Path | None = Field(default=None, description="Filesystem path only; never a URL.")
    auth: Literal["none", "token", "jwt"] | str = "none"
    auth_explicitly_set: bool = Field(
        default=False,
        description="True iff --auth (or IAM_VALIDATOR_MCP_AUTH) was passed explicitly, "
        "as opposed to defaulting to 'none'.",
    )
    profile: Literal["full", "validate-only", "validate-and-query", "read-only"] = "full"
    custom_checks_dir: Path | None = None
    aws_services_dir: Path | None = None
    cache_directory: Path | None = None
    instructions: str | None = None
    instructions_file: Path | None = None
    allowed_regions: frozenset[str] = Field(default_factory=_default_allowed_regions)
    analyze_rate_limit: int = DEFAULT_ANALYZE_RATE_LIMIT
    max_policies: int = DEFAULT_MAX_POLICIES
    max_policy_bytes: int = DEFAULT_MAX_POLICY_BYTES
    max_request_bytes: int = DEFAULT_MAX_REQUEST_BYTES
    request_timeout_s: int = DEFAULT_REQUEST_TIMEOUT_S
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES
    http_max_connections: int = DEFAULT_HTTP_MAX_CONNECTIONS
    http_max_keepalive_connections: int = DEFAULT_HTTP_MAX_KEEPALIVE_CONNECTIONS

    @field_validator("config_source", mode="before")
    @classmethod
    def _reject_url_config_source(cls, v: Any) -> Any:
        if not isinstance(v, str | Path):
            return v
        stripped = str(v).strip()
        if "://" in stripped or _URL_SCHEME_PATTERN.match(stripped):
            raise ValueError(
                f"config_source must be a filesystem path, not a URL: {v!r}. A scheme-like "
                "'word:/' prefix is not accepted (rename or quote the path if it is genuinely "
                "local); mount the config file, or fetch it via ConfigMap/curl in the "
                "entrypoint instead of a URL."
            )
        return stripped if isinstance(v, str) else v

    @field_validator("allowed_regions", mode="before")
    @classmethod
    def _parse_allowed_regions(cls, v: Any) -> Any:
        if isinstance(v, str):
            return [r.strip() for r in v.split(",") if r.strip()]
        return v

    @model_validator(mode="after")
    def _check_instructions_exclusive(self) -> ServerSettings:
        if self.instructions is not None and self.instructions_file is not None:
            raise ValueError("instructions and instructions_file are mutually exclusive; set only one")
        return self

    @model_validator(mode="after")
    def _check_hosted_auth(self) -> ServerSettings:
        if self.mode == "hosted" and self.auth == "none" and not self.auth_explicitly_set:
            raise ValueError(
                "mode='hosted' with auth='none' is only valid when --auth none "
                "(or IAM_VALIDATOR_MCP_AUTH=none) was passed explicitly; refusing to silently "
                "expose an unauthenticated IAM tool over HTTP"
            )
        return self

    @classmethod
    def _env_kwargs(cls, env: Mapping[str, str] | None = None) -> dict[str, Any]:
        """Unvalidated ``IAM_VALIDATOR_MCP_*`` -> field-name kwargs, for layering with CLI flags.

        Returns kwargs rather than a ``ServerSettings`` so no env-only intermediate is
        ever validated -- cross-field validators must only see the merged result.
        """
        source = env if env is not None else os.environ
        kwargs: dict[str, Any] = {}
        for field_name in cls.model_fields:
            if field_name in _ENV_DERIVED_FIELDS:
                continue
            env_name = _ENV_VAR_OVERRIDES.get(field_name, f"{_ENV_PREFIX}{field_name.upper()}")
            if env_name not in source:
                continue
            raw = source[env_name]
            # An env var set but blank (the ordinary way to clear one in compose/k8s) means
            # "unset", not "empty string" -- e.g. IAM_VALIDATOR_MCP_CONFIG= must fall back to
            # the None default, not resolve Path("") to the working directory.
            if raw.strip() == "":
                continue
            kwargs[field_name] = raw
        if "auth" in kwargs:
            kwargs["auth_explicitly_set"] = True
        return kwargs

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> ServerSettings:
        """Build settings from ``IAM_VALIDATOR_MCP_*`` env vars and defaults only.

        Never reads argv, so the Lambda handler can call this with no command line.
        """
        return cls(**cls._env_kwargs(env))
