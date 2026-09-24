"""Tests for mcp/asgi.py's /health and /ready routes."""

import asyncio
import json
from unittest.mock import AsyncMock

import pytest

pytest.importorskip("fastmcp", reason="MCP tests require 'pip install iam-policy-validator[mcp]'")

import httpx  # noqa: E402

from iam_validator.mcp.asgi import create_app  # noqa: E402
from iam_validator.mcp.settings import ServerSettings  # noqa: E402


async def _get(app, path: str, headers: dict[str, str] | None = None) -> httpx.Response:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
        async with app.router.lifespan_context(app):
            return await client.get(path, headers=headers)


def test_health_reports_version_digest_and_source():
    settings = ServerSettings(mode="local", transport="http")
    app = create_app(settings)
    response = asyncio.run(_get(app, "/health"))

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert "version" in body
    assert "config_digest" in body
    assert body["config_source"] == "none"


def test_ready_reports_version_digest_and_source_once_ready():
    settings = ServerSettings(mode="local", transport="http")
    app = create_app(settings)
    response = asyncio.run(_get(app, "/ready"))

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ready"
    assert body["checks"] == {
        "config_resolved": True,
        "registry_built": True,
        "aws_data_ready": True,
    }
    assert "version" in body
    assert "config_digest" in body
    assert body["config_source"] == "none"


def test_health_and_ready_bypass_origin_guard():
    settings = ServerSettings(mode="local", transport="http")
    app = create_app(settings)
    headers = {"Origin": "http://evil.example.com"}

    health = asyncio.run(_get(app, "/health", headers=headers))
    ready = asyncio.run(_get(app, "/ready", headers=headers))

    assert health.status_code == 200
    assert ready.status_code == 200


def test_mcp_route_still_enforces_origin_guard():
    settings = ServerSettings(mode="local", transport="http")
    app = create_app(settings)

    async def post_mcp() -> httpx.Response:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
            async with app.router.lifespan_context(app):
                return await client.post(
                    "/mcp",
                    headers={
                        "Origin": "http://evil.example.com",
                        "Accept": "application/json, text/event-stream",
                        "Content-Type": "application/json",
                    },
                    json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
                )

    response = asyncio.run(post_mcp())
    assert response.status_code == 403


def test_health_and_ready_bypass_auth_provider(monkeypatch, tmp_path):
    monkeypatch.setenv(
        "IAM_VALIDATOR_MCP_AUTH_TOKENS",
        json.dumps({"health-route-test-token": {"client_id": "health-route-test"}}),
    )
    config_file = tmp_path / "iam-validator.yaml"
    config_file.write_text("settings:\n  fail_on_severity: [error, critical]\n")
    settings = ServerSettings(mode="hosted", auth="token", auth_explicitly_set=True, config_source=config_file)
    app = create_app(settings)

    health = asyncio.run(_get(app, "/health"))
    ready = asyncio.run(_get(app, "/ready"))

    assert health.status_code == 200
    assert ready.status_code == 200
    for response in (health, ready):
        body = response.json()
        assert body["config_source"] == "file"
        assert str(config_file) not in response.text
        assert config_file.name not in response.text


def test_mcp_route_still_enforces_auth(monkeypatch, tmp_path):
    monkeypatch.setenv(
        "IAM_VALIDATOR_MCP_AUTH_TOKENS",
        json.dumps({"health-route-test-token": {"client_id": "health-route-test"}}),
    )
    config_file = tmp_path / "iam-validator.yaml"
    config_file.write_text("settings:\n  fail_on_severity: [error, critical]\n")
    settings = ServerSettings(mode="hosted", auth="token", auth_explicitly_set=True, config_source=config_file)
    app = create_app(settings)

    async def post_mcp() -> httpx.Response:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
            async with app.router.lifespan_context(app):
                return await client.post(
                    "/mcp",
                    headers={"Accept": "application/json, text/event-stream", "Content-Type": "application/json"},
                    json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
                )

    response = asyncio.run(post_mcp())
    assert response.status_code == 401


def test_ready_transitions_from_not_ready_to_ready(mock_fetcher, monkeypatch):
    gate = asyncio.Event()

    async def blocking_aenter():
        await gate.wait()
        return mock_fetcher

    mock_fetcher.__aenter__ = AsyncMock(side_effect=blocking_aenter)

    settings = ServerSettings(mode="local", transport="http")
    app = create_app(settings)
    transport = httpx.ASGITransport(app=app)

    entered = asyncio.Event()
    release = asyncio.Event()

    async def run_lifespan():
        async with app.router.lifespan_context(app):
            entered.set()
            await release.wait()

    async def scenario():
        task = asyncio.create_task(run_lifespan())
        async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1") as client:
            await asyncio.sleep(0.05)
            mid = await client.get("/ready")

            gate.set()
            await asyncio.sleep(0.05)
            after = await client.get("/ready")

        release.set()
        await task
        return mid, after

    mid, after = asyncio.run(scenario())

    assert mid.status_code == 503
    assert mid.json()["checks"]["aws_data_ready"] is False
    assert after.status_code == 200
    assert after.json()["checks"]["aws_data_ready"] is True
