"""Guard rails: MCP must source shared literals from core/constants."""

from iam_validator.core import constants
from iam_validator.mcp import server


def test_base_instructions_uses_current_version():
    assert constants.IAM_POLICY_VERSION_CURRENT in server.BASE_INSTRUCTIONS


def test_fix_policy_uses_centralized_versions():
    """Server source must use the constants, not raw "2012-10-17" literals."""
    src_path = server.__file__.replace(".pyc", ".py")
    with open(src_path) as f:
        text = f.read()

    assert "IAM_POLICY_VERSION_CURRENT" in text
    assert "IAM_POLICY_VERSIONS_VALID" in text
    assert '"2012-10-17"' not in text, "Raw policy version literal must come from constants.IAM_POLICY_VERSION_CURRENT"


def test_iam_policy_versions_valid_contains_both():
    assert constants.IAM_POLICY_VERSION_CURRENT in constants.IAM_POLICY_VERSIONS_VALID
    assert constants.IAM_POLICY_VERSION_LEGACY in constants.IAM_POLICY_VERSIONS_VALID
