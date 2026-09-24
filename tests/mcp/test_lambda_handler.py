"""``iam_validator.mcp.awslambda`` -- the Mangum-wrapped Lambda entry point.

The spoofed-header-ignored case is written first, ahead of the legitimate-auth
case: ``AwsGatewayAuthProvider`` (``mcp/auth.py:_AwsGatewayBackend``) must be
provably unmoved by a caller-supplied ``Authorization`` header before any test
asserts that a *real* upstream-verified identity is accepted.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import Mock

import pytest

pytest.importorskip("fastmcp", reason="MCP tests require 'pip install iam-policy-validator[mcp]'")
pytest.importorskip("mangum", reason="Lambda tests require 'pip install iam-policy-validator[lambda]'")

from iam_validator.mcp.awslambda import _check_function_url_auth_type, create_handler  # noqa: E402
from iam_validator.mcp.settings import ServerSettings  # noqa: E402


class _FakeLambdaContext:
    function_name = "iam-validator-mcp-test"
    memory_limit_in_mb = 128
    invoked_function_arn = "arn:aws:lambda:us-east-1:123456789012:function:iam-validator-mcp-test"
    aws_request_id = "test-request-id"


def _function_url_event(body: dict[str, Any], *, authorizer: dict[str, Any] | None, header_auth: str | None) -> dict:
    """A v2.0 (Function URL) event shape, the one Mangum's api_gateway handler expects."""
    headers = {"content-type": "application/json", "accept": "application/json, text/event-stream"}
    if header_auth is not None:
        headers["authorization"] = header_auth
    request_context: dict[str, Any] = {
        "http": {"method": "POST", "path": "/mcp", "sourceIp": "203.0.113.1"},
        "domainName": "test.lambda-url.us-east-1.on.aws",
    }
    if authorizer is not None:
        request_context["authorizer"] = authorizer
    return {
        "version": "2.0",
        "routeKey": "POST /mcp",
        "rawPath": "/mcp",
        "rawQueryString": "",
        "headers": headers,
        "requestContext": request_context,
        "body": json.dumps(body),
        "isBase64Encoded": False,
    }


def _rpc(method: str, params: dict[str, Any] | None = None, *, id_: int = 1) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": id_, "method": method, "params": params or {}}


def _initialize_body() -> dict[str, Any]:
    return _rpc(
        "initialize",
        {
            "protocolVersion": "2026-07-28",
            "capabilities": {},
            "clientInfo": {"name": "test-client", "version": "0"},
        },
    )


def _aws_gateway_settings(tmp_path) -> ServerSettings:
    config_file = tmp_path / "config.yaml"
    config_file.write_text("{}\n")
    return ServerSettings(
        mode="hosted",
        auth="aws-gateway",
        auth_explicitly_set=True,
        config_source=config_file,
        cache_directory=tmp_path / "cache",
    )


def _handler(settings: ServerSettings, monkeypatch: pytest.MonkeyPatch):
    # The Function URL AuthType=NONE self-check is best-effort and only runs when
    # AWS_LAMBDA_FUNCTION_NAME is set; keep it unset so no boto3 call is attempted.
    monkeypatch.delenv("AWS_LAMBDA_FUNCTION_NAME", raising=False)
    return create_handler(settings)


def test_spoofed_authorization_header_is_ignored(tmp_path, monkeypatch: pytest.MonkeyPatch):
    """A caller-supplied bearer token with no ``requestContext.authorizer`` must never authenticate.

    ``_AwsGatewayBackend`` reads claims solely from ``requestContext``; a request
    that carries only a header and no authorizer block must be rejected, exactly
    like an unauthenticated request would be.
    """
    handler = _handler(_aws_gateway_settings(tmp_path), monkeypatch)

    event = _function_url_event(_initialize_body(), authorizer=None, header_auth="Bearer totally-fake-token")
    response = handler(event, _FakeLambdaContext())

    assert response["statusCode"] == 401
    body = json.loads(response["body"])
    assert body["error"] == "invalid_token"


def test_requestcontext_claims_authorize_a_scoped_tool_call(tmp_path, monkeypatch: pytest.MonkeyPatch):
    """A legitimate upstream-verified identity (no header at all) must be authorized.

    This is the case FastMCP's ``RequireAuthMiddleware`` would otherwise 401
    unconditionally, since it gates on ``Authorization`` header *presence* before
    ``scope["user"]`` is ever consulted -- ``_SatisfyBearerPresenceGate`` in
    ``awslambda.py`` exists to keep that gate from blocking every aws-gateway
    request. Only the placeholder header's *presence* matters to that gate; its
    content is never read anywhere, and identity still comes solely from
    ``requestContext.authorizer``.
    """
    handler = _handler(_aws_gateway_settings(tmp_path), monkeypatch)
    authorizer = {"jwt": {"claims": {"sub": "user-1", "scope": "iam:config"}}}

    init_event = _function_url_event(_initialize_body(), authorizer=authorizer, header_auth=None)
    init_response = handler(init_event, _FakeLambdaContext())
    assert init_response["statusCode"] == 200

    call_event = _function_url_event(
        _rpc("tools/call", {"name": "get_config", "arguments": {}}, id_=2),
        authorizer=authorizer,
        header_auth=None,
    )
    call_response = handler(call_event, _FakeLambdaContext())

    assert call_response["statusCode"] == 200
    body = json.loads(call_response["body"])
    assert "error" not in body, body
    assert body["result"]["isError"] is False


class TestFunctionUrlAuthTypeSelfCheck:
    def test_auth_type_none_refuses(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("AWS_LAMBDA_FUNCTION_NAME", "test-fn")
        fake_client = Mock(get_function_url_config=Mock(return_value={"AuthType": "NONE"}))
        monkeypatch.setattr("boto3.client", lambda service: fake_client)

        with pytest.raises(SystemExit):
            _check_function_url_auth_type()

    def test_auth_type_aws_iam_passes(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("AWS_LAMBDA_FUNCTION_NAME", "test-fn")
        fake_client = Mock(get_function_url_config=Mock(return_value={"AuthType": "AWS_IAM"}))
        monkeypatch.setattr("boto3.client", lambda service: fake_client)

        _check_function_url_auth_type()

    def test_non_lambda_environment_skips_the_boto3_call(self, monkeypatch: pytest.MonkeyPatch):
        # A raising side_effect would be swallowed by the function's own broad
        # `except Exception`, so assert non-call via the mock's call tracking instead.
        monkeypatch.delenv("AWS_LAMBDA_FUNCTION_NAME", raising=False)
        client_factory = Mock()
        monkeypatch.setattr("boto3.client", client_factory)

        _check_function_url_auth_type()

        client_factory.assert_not_called()


def test_function_url_iam_authorizer_authenticates_with_no_scopes(tmp_path, monkeypatch: pytest.MonkeyPatch):
    """A Function URL ``AuthType: AWS_IAM`` caller authenticates but gets no OAuth scopes.

    IAM SigV4 auth carries no scope claim, so a scope-gated tool (``get_config``,
    scope ``iam:config``) must be hidden from this caller rather than erroring --
    the same "hide, don't 403" contract ``test_scope_gating.py`` enforces for
    every other auth provider.
    """
    handler = _handler(_aws_gateway_settings(tmp_path), monkeypatch)
    authorizer = {"iam": {"userArn": "arn:aws:iam::123456789012:user/alice", "userId": "AID123"}}

    init_event = _function_url_event(_initialize_body(), authorizer=authorizer, header_auth=None)
    init_response = handler(init_event, _FakeLambdaContext())
    assert init_response["statusCode"] == 200

    list_event = _function_url_event(_rpc("tools/list", id_=2), authorizer=authorizer, header_auth=None)
    list_response = handler(list_event, _FakeLambdaContext())
    assert list_response["statusCode"] == 200
    tool_names = {tool["name"] for tool in json.loads(list_response["body"])["result"]["tools"]}
    assert "get_config" not in tool_names
