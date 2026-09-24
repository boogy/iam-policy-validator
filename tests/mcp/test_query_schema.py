"""Each `kind` branch's required parameter is expressed in inputSchema, not just in code."""

import jsonschema
import pytest
from fastmcp.exceptions import ToolError

from iam_validator.mcp.tools.query import _QUERY_INPUT_SCHEMA, _REQUIRED_PARAM_FOR_KIND, query


@pytest.mark.parametrize("kind,required_param", list(_REQUIRED_PARAM_FOR_KIND.items()))
def test_schema_rejects_kind_missing_its_required_param(kind, required_param):
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(instance={"kind": kind}, schema=_QUERY_INPUT_SCHEMA)


@pytest.mark.parametrize("kind,required_param", list(_REQUIRED_PARAM_FOR_KIND.items()))
def test_schema_accepts_kind_with_its_required_param_present(kind, required_param):
    placeholder = ["x"] if required_param in ("actions", "patterns") else "x"
    jsonschema.validate(instance={"kind": kind, required_param: placeholder}, schema=_QUERY_INPUT_SCHEMA)


@pytest.mark.parametrize("kind,required_param", list(_REQUIRED_PARAM_FOR_KIND.items()))
async def test_missing_required_param_raises_tool_error(kind, required_param):
    with pytest.raises(ToolError, match=required_param):
        await query(kind=kind, ctx=None)
