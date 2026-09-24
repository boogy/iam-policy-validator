"""MCP tools for IAM policy validation and querying.

This package contains the MCP tool implementations organized by category:
- validate: Policy validation tools
- query: AWS service and action query tools
- checks: Check-catalog tools
- config: Organization configuration tools
"""

from iam_validator.mcp.tools.checks import describe_checks
from iam_validator.mcp.tools.config import (
    clear_organization_config_impl,
    get_config,
    get_organization_config_impl,
    load_organization_config_from_yaml_impl,
    set_config,
    set_organization_config_impl,
)
from iam_validator.mcp.tools.query import (
    get_condition_requirements,
    get_policy_summary,
    list_checks,
    list_sensitive_actions,
)

# Aliased: binding "query" here would shadow the "query" submodule other modules import.
from iam_validator.mcp.tools.query import query as query_tool
from iam_validator.mcp.tools.validate import validate_policies

__all__ = [
    # Validation tools
    "validate_policies",
    "query_tool",
    "list_checks",
    "get_policy_summary",
    "list_sensitive_actions",
    "get_condition_requirements",
    "describe_checks",
    # Organization config tools
    "get_config",
    "set_config",
    "set_organization_config_impl",
    "get_organization_config_impl",
    "clear_organization_config_impl",
    "load_organization_config_from_yaml_impl",
]
