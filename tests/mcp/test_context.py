"""Tests for ServerContext: the object that replaces MCP's module-level globals."""

from types import SimpleNamespace

import pytest

from iam_validator.core.check_registry import CheckRegistry
from iam_validator.core.formatters.base import get_global_registry
from iam_validator.core.report import ReportGenerator
from iam_validator.mcp.context import ServerContext, SessionState, build_context, get_server_context
from iam_validator.mcp.settings import ServerSettings

# validate_policy() imports fastmcp.exceptions at call time.
pytest.importorskip("fastmcp", reason="MCP tests require 'pip install iam-policy-validator[mcp]'")


class TestBuildContext:
    """build_context() is the sole place a ServerContext gets constructed."""

    def test_hosted_mode_has_no_mutable_session(self):
        context = build_context(ServerSettings(mode="hosted", auth="token", auth_explicitly_set=True))
        assert context.mutable is None

    def test_local_mode_has_a_session_state(self):
        context = build_context(ServerSettings(mode="local"))
        assert isinstance(context.mutable, SessionState)

    def test_registry_identity_is_stable_across_lookups(self):
        """The registry is built once; repeated tool-style access returns the same object."""
        context = build_context(ServerSettings(mode="local"))
        assert isinstance(context.registry, CheckRegistry)

        first = context.registry
        second = context.registry
        assert first is second

    def test_formatters_populate_the_global_registry_before_anything_reads_it(self):
        """ReportGenerator() must run before anything reads the global FormatterRegistry.

        build_context() constructs ReportGenerator() before the check registry, so by
        the time build_context() returns, the global FormatterRegistry already has the
        built-in formatters registered -- nothing downstream needs to build it lazily.
        """
        context = build_context(ServerSettings(mode="local"))
        assert isinstance(context.formatters, ReportGenerator)

        global_registry = get_global_registry()
        assert global_registry.get_formatter("console") is not None
        assert global_registry.get_formatter("json") is not None


class TestGetServerContext:
    """get_server_context() extracts a ServerContext from a FastMCP-style ctx."""

    def _context(self) -> ServerContext:
        return build_context(ServerSettings(mode="local"))

    def test_extracts_context_from_lifespan(self):
        from types import SimpleNamespace

        context = self._context()
        ctx = SimpleNamespace(request_context=SimpleNamespace(lifespan_context=context))

        assert get_server_context(ctx) is context

    def test_returns_none_when_no_lifespan(self):
        from types import SimpleNamespace

        ctx = SimpleNamespace(request_context=SimpleNamespace(lifespan_context=None))
        assert get_server_context(ctx) is None

    def test_returns_none_for_non_server_context_lifespan(self):
        """A plain dict or namespace masquerading as a lifespan must not be accepted."""
        from types import SimpleNamespace

        ctx = SimpleNamespace(
            request_context=SimpleNamespace(lifespan_context={"aws_sessions": {}}),
        )
        assert get_server_context(ctx) is None

    def test_returns_none_for_bare_object(self):
        assert get_server_context(object()) is None


def _fake_ctx(context: ServerContext) -> SimpleNamespace:
    return SimpleNamespace(request_context=SimpleNamespace(lifespan_context=context))


class TestRegistryBuiltOnceAcrossValidateCalls:
    """The startup registry must survive repeat validate_policy calls unrebuilt.

    ``build_context`` calls ``build_registry`` once; nothing downstream may call
    it again. ``test_registry_identity_is_stable_across_lookups`` above only
    proves ``ServerContext.registry`` is a stable attribute -- it never drives a
    validation call, so it can't catch a callee ignoring that attribute and
    rebuilding its own registry per request.
    """

    def _counting_build_registry(self, monkeypatch: pytest.MonkeyPatch) -> list[int]:
        import iam_validator.core.policy_checks as policy_checks_module

        calls: list[int] = []
        original = policy_checks_module.build_registry

        def counting(*args: object, **kwargs: object) -> object:
            calls.append(1)
            return original(*args, **kwargs)

        monkeypatch.setattr(policy_checks_module, "build_registry", counting)
        return calls

    async def test_validate_policy_does_not_rebuild_registry(self, simple_policy_dict, monkeypatch):
        from iam_validator.mcp.tools.validation import validate_policy

        context = build_context(ServerSettings(mode="local"))
        ctx = _fake_ctx(context)
        calls = self._counting_build_registry(monkeypatch)

        await validate_policy(simple_policy_dict, ctx=ctx)
        await validate_policy(simple_policy_dict, ctx=ctx)

        assert calls == [], f"build_registry ran {len(calls)} time(s) after startup"

    async def test_check_org_compliance_does_not_rebuild_registry(self, simple_policy_dict, monkeypatch):
        from iam_validator.mcp.tools.org_config_tools import check_org_compliance_impl

        context = build_context(ServerSettings(mode="local"))
        ctx = _fake_ctx(context)
        calls = self._counting_build_registry(monkeypatch)

        await check_org_compliance_impl(simple_policy_dict, session=context.mutable, ctx=ctx)
        await check_org_compliance_impl(simple_policy_dict, session=context.mutable, ctx=ctx)

        assert calls == [], f"build_registry ran {len(calls)} time(s) after startup"
