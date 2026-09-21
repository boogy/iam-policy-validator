"""validate_policy/validate_with_config must not touch the filesystem for config."""

from unittest.mock import patch

import pytest

pytest.importorskip("fastmcp", reason="MCP tests require 'pip install iam-policy-validator[mcp]'")

_INLINE_CONFIG = {"settings": {"fail_on_severity": ["error", "critical"]}}


async def test_validate_policy_with_inline_config_does_not_touch_filesystem(simple_policy_dict):
    from iam_validator.mcp.tools.validate import validate_policy

    with patch("tempfile.NamedTemporaryFile") as mock_tempfile:
        result = await validate_policy(policy=simple_policy_dict, config=_INLINE_CONFIG, use_org_config=False)

    mock_tempfile.assert_not_called()
    assert result is not None


async def test_validate_with_config_does_not_touch_filesystem(simple_policy_dict):
    from iam_validator.mcp.tools.config import validate_with_config_impl

    with patch("tempfile.NamedTemporaryFile") as mock_tempfile:
        result = await validate_with_config_impl(policy=simple_policy_dict, config=_INLINE_CONFIG)

    mock_tempfile.assert_not_called()
    assert result["config_applied"] == _INLINE_CONFIG
