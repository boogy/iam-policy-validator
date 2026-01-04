"""MCP tools for IAM policy validation, generation, and querying.

This package contains the MCP tool implementations organized by category:
- validation: Policy validation tools
- generation: Policy generation tools (templates and NL)
- query: AWS service and action query tools
- org_config_tools: Organization configuration tools
"""

from iam_validator.mcp.tools.generation import (
    build_minimal_policy,
    check_sensitive_actions,
    generate_policy_from_template,
    get_required_conditions,
    list_templates,
    suggest_actions,
)
from iam_validator.mcp.tools.org_config_tools import (
    check_org_compliance_impl,
    clear_organization_config_impl,
    get_organization_config_impl,
    load_organization_config_from_yaml_impl,
    set_organization_config_impl,
    validate_with_config_impl,
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
from iam_validator.mcp.tools.validation import (
    quick_validate,
    validate_policy,
    validate_policy_json,
)

__all__ = [
    # Validation tools
    "validate_policy",
    "validate_policy_json",
    "quick_validate",
    # Generation tools
    "generate_policy_from_template",
    "build_minimal_policy",
    "list_templates",
    "suggest_actions",
    "get_required_conditions",
    "check_sensitive_actions",
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
    "check_org_compliance_impl",
    "validate_with_config_impl",
]
