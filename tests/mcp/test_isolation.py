"""Concurrent in-process clients against one hosted server cannot observe each other's state."""

import asyncio
import json
import logging
from types import SimpleNamespace

from iam_validator.core.constants import MCP_AUDIT_LOGGER_NAME
from iam_validator.mcp.context import build_context
from iam_validator.mcp.settings import ServerSettings
from iam_validator.mcp.tools.config import get_config
from tests.mcp.conftest import as_caller


def _fake_ctx(context) -> SimpleNamespace:
    async def _list_tools():
        return []

    return SimpleNamespace(
        request_context=SimpleNamespace(lifespan_context=context),
        fastmcp=SimpleNamespace(list_tools=_list_tools),
    )


def _audit_records(caplog) -> list[dict]:
    return [
        json.loads(r.getMessage())
        for r in caplog.records
        if r.name == MCP_AUDIT_LOGGER_NAME and r.levelno == logging.INFO
    ]


async def test_concurrent_callers_are_never_attributed_to_each_other(tmp_path, caplog):
    caplog.set_level(logging.INFO)
    config_file = tmp_path / "iam-validator.yaml"
    config_file.write_text("settings:\n  fail_on_severity: [error, critical]\n")
    settings = ServerSettings(mode="hosted", auth="token", auth_explicitly_set=True, config_source=config_file)
    context = build_context(settings)
    ctx = _fake_ctx(context)

    async def _call(client_id: str) -> None:
        with as_caller("iam:config", client_id=client_id):
            await asyncio.sleep(0)
            await get_config(ctx)

    await asyncio.gather(_call("caller-a"), _call("caller-b"))

    records = _audit_records(caplog)
    subjects = {r["subject"] for r in records if r["tool"] == "get_config"}
    assert subjects == {"caller-a", "caller-b"}
