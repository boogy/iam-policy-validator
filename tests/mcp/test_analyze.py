"""Tests for the AWS Access Analyzer MCP integration.

Mocks at the boto3 boundary — no real AWS calls.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from fastmcp.exceptions import ToolError

from iam_validator.mcp.context import AnalyzeRateLimiter, ServerContext
from iam_validator.mcp.settings import ServerSettings
from iam_validator.mcp.tools import analyze
from iam_validator.mcp.tools.analyze import analyze_policy


def _fake_server_context(*, settings: ServerSettings | None = None) -> ServerContext:
    """A minimal ServerContext for tests that only exercise aws_sessions."""
    resolved_settings = settings or ServerSettings(allowed_regions=frozenset())
    return ServerContext(
        config=MagicMock(),
        registry=MagicMock(),
        formatters=MagicMock(),
        fetcher=MagicMock(),
        aws_sessions={},
        settings=resolved_settings,
        mutable=None,
        analyze_rate_limiter=AnalyzeRateLimiter(resolved_settings.analyze_rate_limit),
    )


def _fake_ctx(context: ServerContext) -> SimpleNamespace:
    return SimpleNamespace(request_context=SimpleNamespace(lifespan_context=context))


@pytest.fixture
def mock_session():
    """boto3.Session mock returning a client whose validate_policy returns one finding."""
    response = {
        "findings": [
            {
                "findingType": "ERROR",
                "issueCode": "INVALID_ACTION",
                "findingDetails": "Action s3:GetObjects does not exist.",
                "learnMoreLink": "https://docs.aws.amazon.com/access-analyzer/findings",
                "locations": [
                    {
                        "path": [{"value": "Statement"}],
                        "span": {
                            "start": {"line": 1, "column": 1, "offset": 0},
                            "end": {"line": 1, "column": 10, "offset": 10},
                        },
                    }
                ],
            }
        ]
    }
    client = MagicMock()
    client.validate_policy.return_value = response
    sess = MagicMock()
    sess.client.return_value = client
    return sess


async def test_analyze_returns_findings(mock_session):
    result = await analyze_policy(
        {"Version": "2012-10-17", "Statement": []},
        session=mock_session,
    )
    assert result["finding_count"] == 1
    assert result["findings"][0]["issue_code"] == "INVALID_ACTION"
    assert result["findings"][0]["finding_type"] == "ERROR"


async def test_analyze_invalid_policy_type_raises():
    with pytest.raises(ToolError, match="Invalid policy_type"):
        await analyze_policy({}, policy_type="BOGUS")


def test_get_aws_session_caches_per_region_profile(monkeypatch):
    """Same (region, profile) returns the same Session; different keys do not."""
    from iam_validator.mcp.context import get_aws_session

    created: list = []

    class FakeSession:
        def __init__(self, **kw):
            created.append(kw)
            self.kw = kw

    monkeypatch.setattr("boto3.Session", FakeSession)

    ctx = SimpleNamespace(request_context=SimpleNamespace(lifespan_context=_fake_server_context()))

    a1 = get_aws_session(ctx, "us-east-1", None)
    a2 = get_aws_session(ctx, "us-east-1", None)
    b = get_aws_session(ctx, "us-west-2", None)

    assert a1 is a2, "Same key must return the same Session"
    assert a1 is not b, "Different region must yield a different Session"
    assert len(created) == 2, "Only two Session() constructions: us-east-1, us-west-2"


def test_get_aws_session_falls_back_when_no_lifespan(monkeypatch):
    """Tests / direct callers without an MCP lifespan must not crash."""
    from iam_validator.mcp.context import get_aws_session

    class FakeSession:
        def __init__(self, **kw):
            self.kw = kw

    monkeypatch.setattr("boto3.Session", FakeSession)

    ctx = SimpleNamespace(request_context=SimpleNamespace(lifespan_context=None))
    s = get_aws_session(ctx, "eu-west-1", None)
    assert s.kw == {"region_name": "eu-west-1"}


def test_get_aws_session_includes_profile_when_set(monkeypatch):
    """profile= must propagate into the Session constructor."""
    from iam_validator.mcp.context import get_aws_session

    class FakeSession:
        def __init__(self, **kw):
            self.kw = kw

    monkeypatch.setattr("boto3.Session", FakeSession)

    ctx = SimpleNamespace(request_context=SimpleNamespace(lifespan_context=_fake_server_context()))
    s = get_aws_session(ctx, "us-east-1", "my-profile")
    assert s.kw == {"region_name": "us-east-1", "profile_name": "my-profile"}


class TestHostedSchema:
    async def test_hosted_schema_has_no_profile_parameter(self):
        from iam_validator.mcp.build import build_server

        hosted = build_server(ServerSettings(mode="hosted", auth="none", auth_explicitly_set=True))
        tools = await hosted.list_tools()
        ap = next(t for t in tools if t.name == "analyze_policy")
        assert "profile" not in ap.parameters.get("properties", {})

    async def test_local_schema_has_profile_parameter(self):
        from iam_validator.mcp.build import build_server

        local = build_server(ServerSettings(mode="local"))
        tools = await local.list_tools()
        ap = next(t for t in tools if t.name == "analyze_policy")
        assert "profile" in ap.parameters.get("properties", {})


class TestOpenWorldHint:
    async def test_analyze_policy_is_the_only_open_world_tool(self):
        from iam_validator.mcp.build import build_server

        server = build_server(ServerSettings(mode="local"))
        tools = await server.list_tools()
        open_world = [t.name for t in tools if t.annotations and t.annotations.openWorldHint]
        assert open_world == ["analyze_policy"]


class TestRegionAllowlist:
    async def test_region_outside_allowlist_raises_without_creating_session(self, monkeypatch):
        monkeypatch.setattr(analyze, "analyze_policy", MagicMock())  # must never be reached
        context = _fake_server_context(settings=ServerSettings(allowed_regions=frozenset({"us-east-1"})))
        ctx = _fake_ctx(context)

        with pytest.raises(ToolError, match="us-east-1"):
            await analyze._analyze_policy_tool(
                policy={"Version": "2012-10-17", "Statement": []}, ctx=ctx, region="eu-west-1"
            )
        assert context.aws_sessions == {}

    async def test_region_inside_allowlist_is_permitted(self, monkeypatch, mock_session):
        monkeypatch.setattr(analyze, "get_aws_session", lambda ctx, region, profile: mock_session)
        context = _fake_server_context(settings=ServerSettings(allowed_regions=frozenset({"us-east-1"})))
        ctx = _fake_ctx(context)

        result = await analyze._analyze_policy_tool(
            policy={"Version": "2012-10-17", "Statement": []}, ctx=ctx, region="us-east-1"
        )
        assert result["finding_count"] == 1

    async def test_empty_allowlist_is_unrestricted(self, monkeypatch, mock_session):
        monkeypatch.setattr(analyze, "get_aws_session", lambda ctx, region, profile: mock_session)
        context = _fake_server_context(settings=ServerSettings(allowed_regions=frozenset()))
        ctx = _fake_ctx(context)

        result = await analyze._analyze_policy_tool(
            policy={"Version": "2012-10-17", "Statement": []}, ctx=ctx, region="ap-southeast-2"
        )
        assert result["finding_count"] == 1


class TestAnalyzeRateLimit:
    async def test_rate_limit_allows_up_to_the_cap_then_rejects(self, monkeypatch, mock_session):
        monkeypatch.setattr(analyze, "get_aws_session", lambda ctx, region, profile: mock_session)
        context = _fake_server_context(settings=ServerSettings(analyze_rate_limit=2))
        ctx = _fake_ctx(context)

        await analyze._analyze_policy_tool(policy={"Version": "2012-10-17", "Statement": []}, ctx=ctx)
        await analyze._analyze_policy_tool(policy={"Version": "2012-10-17", "Statement": []}, ctx=ctx)
        with pytest.raises(ToolError, match="rate limit"):
            await analyze._analyze_policy_tool(policy={"Version": "2012-10-17", "Statement": []}, ctx=ctx)

    async def test_zero_disables_the_cap(self, monkeypatch, mock_session):
        monkeypatch.setattr(analyze, "get_aws_session", lambda ctx, region, profile: mock_session)
        context = _fake_server_context(settings=ServerSettings(analyze_rate_limit=0))
        ctx = _fake_ctx(context)

        for _ in range(5):
            result = await analyze._analyze_policy_tool(policy={"Version": "2012-10-17", "Statement": []}, ctx=ctx)
            assert result["finding_count"] == 1
