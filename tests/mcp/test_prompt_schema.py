"""Guard: prompt argument descriptions must stay exactly what the docstring says."""

from fastmcp.client import Client

from iam_validator.mcp.build import build_server
from iam_validator.mcp.settings import ServerSettings

_GENERIC_SCHEMA_FALLBACK = "Provide a value matching the following JSON schema"


async def test_no_prompt_argument_description_has_generic_schema_fallback():
    mcp = build_server(ServerSettings())
    async with Client(mcp) as client:
        prompts = await client.list_prompts()

    assert prompts, "expected at least one registered prompt"
    for prompt in prompts:
        for argument in prompt.arguments or []:
            assert _GENERIC_SCHEMA_FALLBACK not in (argument.description or ""), (
                f"{prompt.name}.{argument.name} description was overridden by FastMCP's "
                "generic schema fallback (likely `from __future__ import annotations` in "
                "prompts.py)"
            )
