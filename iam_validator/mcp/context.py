"""Server-wide context, built once at startup and threaded through every call.

``ServerContext`` replaces the module-level globals that used to make MCP tool
behavior depend on process-wide mutable state: the ``aws_sessions`` dict, the
``functools.lru_cache``-backed registry singleton, and the classmethod-based
``SessionConfigManager``/``CustomInstructionsManager`` (deleted; superseded by
``SessionState``). It is built once via
:func:`build_context`, entered into the FastMCP lifespan by :func:`server_lifespan`,
and reached from tool/resource bodies via ``ctx.request_context.lifespan_context``
(see :func:`get_server_context`).
"""

from __future__ import annotations

import logging
import threading
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import yaml

from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.check_registry import CheckRegistry, create_default_registry
from iam_validator.core.config.config_loader import ConfigLoader, ValidatorConfig
from iam_validator.core.policy_checks import build_registry
from iam_validator.core.report import ReportGenerator
from iam_validator.mcp.settings import ServerSettings

if TYPE_CHECKING:
    from fastmcp import FastMCP

logger = logging.getLogger(__name__)


class SessionState:
    """Session-scoped mutable state for local-mode tools: org config + custom instructions.

    Held on ``ServerContext.mutable``. Absent (``None``) in hosted mode, where
    per-caller mutation of validator behavior is not exposed (see TASK-07).
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._config: ValidatorConfig | None = None
        self._config_source: str = "none"
        self._instructions: str | None = None
        self._instructions_source: str = "none"

    # --- organization config ---

    def set_config(self, config_dict: dict[str, Any], source: str = "session") -> ValidatorConfig:
        with self._lock:
            self._config = ValidatorConfig(config_dict, use_defaults=True)
            self._config_source = source
            return self._config

    def get_config(self) -> ValidatorConfig | None:
        with self._lock:
            return self._config

    def get_config_source(self) -> str:
        with self._lock:
            return self._config_source

    def clear_config(self) -> bool:
        with self._lock:
            had_config = self._config is not None
            self._config = None
            self._config_source = "none"
            return had_config

    def has_config(self) -> bool:
        with self._lock:
            return self._config is not None

    def load_config_from_yaml(self, yaml_content: str) -> tuple[ValidatorConfig, list[str]]:
        """Parse and apply a YAML config, migrating legacy keys.

        Raises:
            ValueError: Invalid YAML, or YAML that isn't a mapping.
        """
        warnings: list[str] = []

        try:
            config_dict = yaml.safe_load(yaml_content)
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML: {e}") from e

        if not isinstance(config_dict, dict):
            raise ValueError("YAML content must be a dictionary")

        # Support legacy "organization" key for backwards compatibility.
        if "organization" in config_dict:
            org_config = config_dict.pop("organization")
            config_dict.setdefault("settings", {}).update(org_config)
            warnings.append("Migrated 'organization' key to 'settings'")

        # Extract custom_instructions if present (MCP-specific setting).
        if "custom_instructions" in config_dict:
            custom_instructions = config_dict.pop("custom_instructions")
            if isinstance(custom_instructions, str) and custom_instructions.strip():
                self.set_instructions(custom_instructions, source="config")
                warnings.append("Loaded custom instructions from config")

        config = self.set_config(config_dict, source="yaml")
        return config, warnings

    # --- custom instructions ---

    def set_instructions(self, instructions: str, source: str = "api") -> None:
        with self._lock:
            stripped = instructions.strip() if instructions else ""
            self._instructions = stripped if stripped else None
            self._instructions_source = source if self._instructions else "none"

    def get_instructions(self) -> str | None:
        with self._lock:
            return self._instructions

    def get_instructions_source(self) -> str:
        with self._lock:
            return self._instructions_source

    def clear_instructions(self) -> bool:
        with self._lock:
            had_instructions = self._instructions is not None
            self._instructions = None
            self._instructions_source = "none"
            return had_instructions

    def has_instructions(self) -> bool:
        with self._lock:
            return self._instructions is not None


@dataclass
class ServerContext:
    """Everything a tool call needs, built once and shared across the server's lifetime."""

    config: ValidatorConfig
    registry: CheckRegistry
    formatters: ReportGenerator
    fetcher: AWSServiceFetcher
    aws_sessions: dict[tuple[str, str | None], Any]
    settings: ServerSettings
    mutable: SessionState | None
    # Unimplemented seam for TASK-07 (hosted/local config resolution + digest).
    config_digest: str | None = None
    # Set True once the fetcher prewarm completes; TASK-19's /ready endpoint reads this.
    ready: bool = False


def _load_config(settings: ServerSettings) -> ValidatorConfig:
    explicit_path = str(settings.config_source) if settings.config_source else None
    return ConfigLoader.load_config(explicit_path=explicit_path, allow_missing=True)


def build_context(settings: ServerSettings) -> ServerContext:
    """Construct a ``ServerContext`` from resolved settings.

    Synchronous and network-free: the returned fetcher is constructed but not
    yet entered (see :func:`prewarm`). ``ReportGenerator()`` is constructed
    before the registry so the global ``FormatterRegistry`` is populated before
    anything else in the context could read it.
    """
    formatters = ReportGenerator()

    config = _load_config(settings)

    # Local mode: an explicit custom_checks_dir is caller consent; a YAML-only
    # one is not. Hosted mode inverts this for the server's own operator config.
    registry = build_registry(
        config,
        custom_checks_dir=str(settings.custom_checks_dir) if settings.custom_checks_dir else None,
        allow_config_custom_checks=(settings.mode == "hosted"),
    )

    fetcher = AWSServiceFetcher(
        prefetch_common=True,
        memory_cache_size=512,
        aws_services_dir=str(settings.aws_services_dir) if settings.aws_services_dir else None,
        cache_dir=str(settings.cache_directory) if settings.cache_directory else None,
    )

    mutable = None if settings.mode == "hosted" else SessionState()

    return ServerContext(
        config=config,
        registry=registry,
        formatters=formatters,
        fetcher=fetcher,
        aws_sessions={},
        settings=settings,
        mutable=mutable,
    )


async def prewarm(context: ServerContext) -> None:
    """Enter the shared fetcher (pre-fetching common services) and mark ready."""
    await context.fetcher.__aenter__()
    context.ready = True


def _resolve_startup_instructions(settings: ServerSettings) -> str | None:
    """Custom instructions from settings: inline text takes precedence over a file."""
    if settings.instructions:
        return settings.instructions
    if settings.instructions_file:
        return settings.instructions_file.read_text()
    return None


@asynccontextmanager
async def server_lifespan(_server: FastMCP, settings: ServerSettings | None = None) -> AsyncIterator[ServerContext]:
    """FastMCP lifespan: build the context once, prewarm it, and tear it down on exit.

    ``settings`` lets ``build_server()`` thread the same settings it used for
    tool/resource gating into the runtime context (so e.g. ``get_active_profile``
    reports the profile that was actually built); falls back to
    ``ServerSettings.from_env()`` when constructed directly.
    """
    if settings is None:
        settings = ServerSettings.from_env()
    context = build_context(settings)

    custom_instructions = _resolve_startup_instructions(settings)
    if context.mutable is not None and custom_instructions:
        context.mutable.set_instructions(custom_instructions, source="settings")

    await prewarm(context)

    from iam_validator.mcp.instructions import get_instructions

    _server.instructions = get_instructions(custom_instructions)

    try:
        yield context
    finally:
        await context.fetcher.__aexit__(None, None, None)


def get_server_context(ctx: Any) -> ServerContext | None:
    """Extract the ``ServerContext`` from a FastMCP tool/resource ``Context``.

    Returns ``None`` outside of an MCP request (tests, direct calls) rather
    than raising, mirroring the previous globals' test-friendly fallback.
    """
    lifespan = getattr(getattr(ctx, "request_context", None), "lifespan_context", None)
    return lifespan if isinstance(lifespan, ServerContext) else None


def get_aws_session(ctx: Any, region: str, profile: str | None) -> Any:
    """Return a (cached) boto3 Session for ``(region, profile)``.

    Mirrors ``get_shared_fetcher``'s fallback: if no lifespan context is
    available (tests, direct calls outside MCP), build a fresh session each
    call rather than crashing.
    """
    import boto3

    context = get_server_context(ctx)
    cache = context.aws_sessions if context is not None else None

    if cache is None:
        kwargs: dict[str, Any] = {"region_name": region}
        if profile:
            kwargs["profile_name"] = profile
        return boto3.Session(**kwargs)

    key = (region, profile)
    if key not in cache:
        kwargs = {"region_name": region}
        if profile:
            kwargs["profile_name"] = profile
        cache[key] = boto3.Session(**kwargs)
    return cache[key]


def get_shared_fetcher(ctx: Any) -> AWSServiceFetcher | None:
    """Get the shared AWSServiceFetcher from context.

    Returns ``None`` if not available (tests, direct calls outside MCP);
    callers typically create a new fetcher instance in that case. Logged at
    DEBUG level since this happens routinely outside of an MCP request.
    """
    context = get_server_context(ctx)
    if context is not None:
        return context.fetcher

    logger.debug("Shared fetcher unavailable from context; tool will create a new one.")
    return None


def effective_check_settings(check_id: str, default_severity: str, ctx: Any) -> tuple[bool, str]:
    """``(enabled, severity)`` after the session config that validate_policy applies."""
    context = get_server_context(ctx)
    config = context.mutable.get_config() if context is not None and context.mutable is not None else None
    if config is None:
        return True, default_severity
    return (
        config.is_check_enabled(check_id),
        config.get_check_severity(check_id) or default_severity,
    )


def get_check_catalog(ctx: Any = None) -> tuple[dict[str, Any], ...]:
    """Every registered check, with session-config enablement and severity resolved.

    Not cached: the session config can change between calls.
    """
    context = get_server_context(ctx)
    registry = context.registry if context is not None else create_default_registry()

    catalog: list[dict[str, Any]] = []
    for check_instance in registry.get_all_checks():
        enabled, severity = effective_check_settings(check_instance.check_id, check_instance.default_severity, ctx)
        catalog.append(
            {
                "check_id": check_instance.check_id,
                "description": check_instance.description,
                "default_severity": check_instance.default_severity,
                "severity": severity,
                "enabled": enabled,
            }
        )
    return tuple(sorted(catalog, key=lambda x: x["check_id"]))


def get_check_details(check_id: str, ctx: Any = None) -> dict[str, Any]:
    """Get full documentation for a validation check (registry-driven).

    Backs the parameterised MCP resource ``iam://checks/{check_id}``.

    Returns:
        {check_id, description, default_severity, category, example_violation,
         example_fix, configuration, related}
    """
    context = get_server_context(ctx)
    registry = context.registry if context is not None else create_default_registry()
    check = registry.get_check(check_id)

    if check is None:
        return {
            "check_id": check_id,
            "description": "Check not found",
            "default_severity": None,
            "category": "unknown",
            "example_violation": None,
            "example_fix": None,
            "configuration": {},
            "related": [],
        }

    enabled, severity = effective_check_settings(check_id, check.default_severity, ctx)

    return {
        "check_id": check_id,
        "description": check.description,
        "default_severity": check.default_severity,
        "category": "general",
        "example_violation": None,
        "example_fix": None,
        "configuration": {"enabled": enabled, "severity": severity},
        "related": [],
    }


__all__ = [
    "ServerContext",
    "SessionState",
    "build_context",
    "prewarm",
    "server_lifespan",
    "get_server_context",
    "get_aws_session",
    "get_shared_fetcher",
    "effective_check_settings",
    "get_check_catalog",
    "get_check_details",
]
