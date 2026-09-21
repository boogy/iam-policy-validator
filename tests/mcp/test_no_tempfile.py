"""validate_policies must not touch the filesystem for inline policy input."""

from unittest.mock import patch

import pytest

pytest.importorskip("fastmcp", reason="MCP tests require 'pip install iam-policy-validator[mcp]'")


async def test_validate_policies_inline_dict_does_not_touch_filesystem(simple_policy_dict):
    from iam_validator.mcp.tools.validate import validate_policies

    with patch("tempfile.NamedTemporaryFile") as mock_tempfile:
        result = await validate_policies(policies=[simple_policy_dict])

    mock_tempfile.assert_not_called()
    assert result is not None


async def test_validate_policies_inline_json_string_does_not_touch_filesystem(simple_policy_dict):
    import json

    from iam_validator.mcp.tools.validate import validate_policies

    with patch("tempfile.NamedTemporaryFile") as mock_tempfile:
        result = await validate_policies(policies=[json.dumps(simple_policy_dict)])

    mock_tempfile.assert_not_called()
    assert result is not None
