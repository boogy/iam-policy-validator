"""MCP tools for IAM policy validation and querying.

This package contains the MCP tool implementations organized by category:
- validate: Policy validation tools
- query: AWS service and action query tools
- config: Organization configuration tools
"""

from iam_validator.mcp.tools.config import (
    clear_organization_config_impl,
    get_organization_config_impl,
    load_organization_config_from_yaml_impl,
    set_organization_config_impl,
)
from iam_validator.mcp.tools.query import (
    expand_wildcard_action,
    get_condition_requirements,
    get_policy_summary,
    list_checks,
    list_sensitive_actions,
    query_action_details,
    query_arn_formats,
    query_condition_keys,
    query_service_actions,
)
from iam_validator.mcp.tools.validate import validate_policies

__all__ = [
    # Validation tools
    "validate_policies",
    # Query tools
    "query_service_actions",
    "query_action_details",
    "expand_wildcard_action",
    "query_condition_keys",
    "query_arn_formats",
    "list_checks",
    "get_policy_summary",
    "list_sensitive_actions",
    "get_condition_requirements",
    # Organization config tools
    "set_organization_config_impl",
    "get_organization_config_impl",
    "clear_organization_config_impl",
    "load_organization_config_from_yaml_impl",
]
