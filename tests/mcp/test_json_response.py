"""``json_response=True`` app tests.

Lambda's Python managed runtime cannot stream ``text/event-stream`` (API Gateway
buffers regardless), so a Lambda-fronted app must run with ``json_response=True``:
every tool call has to complete as a single JSON response with no server-initiated
message (progress, logging, sampling) in between, and the SSE-only ``GET /mcp``
channel is rejected outright.
"""

from __future__ import annotations

import ast
from pathlib import Path

import httpx
import pytest
from fastmcp.client import Client
from fastmcp.client.transports import StreamableHttpTransport

from iam_validator.core.access_analyzer import AccessAnalyzerValidator
from iam_validator.mcp.build import build_server
from iam_validator.mcp.settings import ServerSettings

REPO_ROOT = Path(__file__).resolve().parents[2]
MCP_ROOT = REPO_ROOT / "iam_validator" / "mcp"

# stateless_http+json_response silently drops these rather than delivering or erroring
# (proven by injecting a call into a tool and observing a client message_handler never
# sees it), so a runtime test can't catch a regression here -- this must be static.
_NOTIFICATION_CTX_METHODS = frozenset(
    {"report_progress", "log", "info", "debug", "warning", "error", "send_notification", "elicit", "sample"}
)


def _is_ctx_or_its_request_context(node: ast.expr) -> bool:
    """Matches ``ctx`` and ``ctx.request_context`` -- both resolve to the same session."""
    if isinstance(node, ast.Name):
        return node.id == "ctx"
    return (
        isinstance(node, ast.Attribute)
        and node.attr == "request_context"
        and _is_ctx_or_its_request_context(node.value)
    )


def _ctx_notification_calls(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(), filename=str(path))
    hits = [
        f"{node.func.attr}() at line {node.lineno}"
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr in _NOTIFICATION_CTX_METHODS
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "ctx"
    ]
    # The raw ServerSession bypasses the banned-method list, so any access through it is banned.
    hits += [
        f"session access at line {node.lineno}"
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute) and node.attr == "session" and _is_ctx_or_its_request_context(node.value)
    ]
    return hits


def test_no_handler_calls_a_server_initiated_notification_method():
    hits = {
        str(path.relative_to(REPO_ROOT)): calls
        for path in sorted(MCP_ROOT.rglob("*.py"))
        if (calls := _ctx_notification_calls(path))
    }
    assert not hits, (
        f"handler(s) call a notification-causing Context method, dropped silently under json_response: {hits}"
    )


# One representative, schema-valid call per registered tool.
TOOL_CALLS = {
    "validate_policies": {
        "policies": [
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}],
            }
        ]
    },
    "query": {"kind": "expand_wildcard", "patterns": ["s3:Get*"]},
    "describe_checks": {},
    "get_config": {},
    "set_config": {"clear_config": True},
    "analyze_policy": {"policy": {"Version": "2012-10-17", "Statement": []}},
}


def _json_response_client(message_handler) -> tuple[httpx.ASGITransport, object, Client]:
    mcp = build_server(ServerSettings())
    app = mcp.http_app(stateless_http=True, json_response=True)

    def factory(**kwargs):
        # StreamableHttpTransport always passes follow_redirects; ASGITransport rejects it.
        kwargs.pop("follow_redirects", None)
        return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test", **kwargs)

    transport = StreamableHttpTransport("http://test/mcp", httpx_client_factory=factory)
    return app, Client(transport, message_handler=message_handler)


async def test_every_tool_completes_successfully_under_json_response(monkeypatch: pytest.MonkeyPatch):
    """Every tool must return its final result as a single JSON response, with no mid-call frame required."""
    monkeypatch.setattr(AccessAnalyzerValidator, "validate_policy", lambda self, policy_document: [])

    async def _record(message):
        pass

    app, client = _json_response_client(_record)
    async with app.router.lifespan_context(app):
        async with client:
            tools = {t.name for t in await client.list_tools()}
            assert tools == set(TOOL_CALLS), "add a TOOL_CALLS entry for any newly registered tool"
            for name, args in TOOL_CALLS.items():
                result = await client.call_tool(name, args)
                assert not result.is_error, f"{name} failed: {result.content}"


async def test_get_mcp_is_rejected_under_json_response():
    """The GET SSE channel is optional and unsupported here; Lambda has nothing to serve it with."""
    mcp = build_server(ServerSettings())
    app = mcp.http_app(stateless_http=True, json_response=True)
    transport = httpx.ASGITransport(app=app)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as http_client:
            response = await http_client.get("/mcp", headers={"Accept": "application/json, text/event-stream"})

    assert response.status_code == 405
