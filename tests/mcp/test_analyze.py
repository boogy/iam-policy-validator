"""Tests for the AWS Access Analyzer MCP integration.

Mocks at the boto3 boundary — no real AWS calls.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from fastmcp.exceptions import ToolError

from iam_validator.mcp.tools.analyze import analyze_policy


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
    from iam_validator.mcp.server import get_aws_session

    created: list = []

    class FakeSession:
        def __init__(self, **kw):
            created.append(kw)
            self.kw = kw

    monkeypatch.setattr("boto3.Session", FakeSession)

    cache: dict = {}
    ctx = SimpleNamespace(request_context=SimpleNamespace(lifespan_context={"aws_sessions": cache}))

    a1 = get_aws_session(ctx, "us-east-1", None)
    a2 = get_aws_session(ctx, "us-east-1", None)
    b = get_aws_session(ctx, "us-west-2", None)

    assert a1 is a2, "Same key must return the same Session"
    assert a1 is not b, "Different region must yield a different Session"
    assert len(created) == 2, "Only two Session() constructions: us-east-1, us-west-2"


def test_get_aws_session_falls_back_when_no_lifespan(monkeypatch):
    """Tests / direct callers without an MCP lifespan must not crash."""
    from iam_validator.mcp.server import get_aws_session

    class FakeSession:
        def __init__(self, **kw):
            self.kw = kw

    monkeypatch.setattr("boto3.Session", FakeSession)

    ctx = SimpleNamespace(request_context=SimpleNamespace(lifespan_context=None))
    s = get_aws_session(ctx, "eu-west-1", None)
    assert s.kw == {"region_name": "eu-west-1"}


def test_get_aws_session_includes_profile_when_set(monkeypatch):
    """profile= must propagate into the Session constructor."""
    from iam_validator.mcp.server import get_aws_session

    class FakeSession:
        def __init__(self, **kw):
            self.kw = kw

    monkeypatch.setattr("boto3.Session", FakeSession)

    cache: dict = {}
    ctx = SimpleNamespace(request_context=SimpleNamespace(lifespan_context={"aws_sessions": cache}))
    s = get_aws_session(ctx, "us-east-1", "my-profile")
    assert s.kw == {"region_name": "us-east-1", "profile_name": "my-profile"}
