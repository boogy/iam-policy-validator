"""
Core configuration modules for IAM Policy Validator.

This package contains default configuration data used by validators, organized into
logical modules for better maintainability and performance.

All configuration is defined as Python code (not YAML/JSON) for:
- Faster loading (no parsing overhead)
- Better PyPI packaging (no data files to manage)
- Type hints and IDE support
- Compiled to .pyc for even faster imports

Performance benefits:
- 5-10x faster than YAML parsing
- Zero runtime parsing overhead
- Lazy loading support
- O(1) frozenset lookups
"""

from iam_validator.core.config.aws_api import (
    AWS_SERVICE_REFERENCE_BASE_URL,
    get_service_reference_url,
)
from iam_validator.core.config.condition_requirements import (
    ALL_CONDITION_REQUIREMENTS,
    DEFAULT_CONDITION_REQUIREMENTS,
    get_all_requirement_names,
    get_default_requirements,
    get_requirement,
    get_requirements_by_names,
    get_requirements_by_severity,
)
from iam_validator.core.config.defaults import DEFAULT_CONFIG
from iam_validator.core.config.principal_requirements import (
    ALL_PRINCIPAL_REQUIREMENTS,
    DEFAULT_ENABLED_REQUIREMENTS,
    get_all_principal_requirement_names,
    get_default_principal_requirements,
    get_principal_requirement,
    get_principal_requirements_by_names,
    get_principal_requirements_by_severity,
)
from iam_validator.core.config.sensitive_actions import (
    DEFAULT_SENSITIVE_ACTIONS,
    get_sensitive_actions,
)
from iam_validator.core.config.service_principals import DEFAULT_SERVICE_PRINCIPALS
from iam_validator.core.config.wildcards import (
    DEFAULT_ALLOWED_WILDCARDS,
    DEFAULT_SERVICE_WILDCARDS,
)

__all__ = [
    # Default configuration
    "DEFAULT_CONFIG",
    # AWS API endpoints
    "AWS_SERVICE_REFERENCE_BASE_URL",
    "get_service_reference_url",
    # Sensitive actions
    "DEFAULT_SENSITIVE_ACTIONS",
    "get_sensitive_actions",
    # Condition requirements (for actions)
    "DEFAULT_CONDITION_REQUIREMENTS",
    "ALL_CONDITION_REQUIREMENTS",
    "get_default_requirements",
    "get_requirement",
    "get_all_requirement_names",
    "get_requirements_by_names",
    "get_requirements_by_severity",
    # Principal requirements (for principals)
    "ALL_PRINCIPAL_REQUIREMENTS",
    "DEFAULT_ENABLED_REQUIREMENTS",
    "get_default_principal_requirements",
    "get_principal_requirement",
    "get_all_principal_requirement_names",
    "get_principal_requirements_by_names",
    "get_principal_requirements_by_severity",
    # Wildcards
    "DEFAULT_ALLOWED_WILDCARDS",
    "DEFAULT_SERVICE_WILDCARDS",
    # Service principals
    "DEFAULT_SERVICE_PRINCIPALS",
]
