"""IAM policy templates for MCP server.

This package provides built-in policy templates that can be used to generate
common IAM policies with variable substitution. Templates are validated
through the security enforcement layer before being returned.

Available templates:
- s3-read-only: S3 bucket read-only access
- s3-read-write: S3 bucket read-write access
- lambda-basic-execution: Basic Lambda execution role
- lambda-s3-trigger: Lambda with S3 event trigger permissions
- dynamodb-crud: DynamoDB table CRUD operations
- cloudwatch-logs: CloudWatch Logs write permissions
- secrets-manager-read: Secrets Manager read access
- kms-encrypt-decrypt: KMS key encryption/decryption
- ec2-describe: EC2 describe-only permissions
- ecs-task-execution: ECS task execution role
"""

from .builtin import get_template as _get_template
from .builtin import list_templates as _list_templates
from .builtin import render_template as _render_template


def list_templates() -> list[str]:
    """List all available template names.

    Returns:
        List of template names that can be used with load_template()
    """
    templates = _list_templates()
    return [t["name"] for t in templates]


def get_template_variables(template_name: str) -> list[str]:
    """Get the required variables for a template.

    Args:
        template_name: Name of the template

    Returns:
        List of variable names required by the template

    Raises:
        ValueError: If template_name is not found
    """
    template = _get_template(template_name)
    if not template:
        raise ValueError(
            f"Template '{template_name}' not found. "
            f"Available templates: {', '.join(list_templates())}"
        )

    return [var["name"] for var in template["variables"]]


def load_template(template_name: str, variables: dict[str, str] | None = None) -> dict:
    """Load a template and substitute variables.

    Args:
        template_name: Name of the template to load
        variables: Dictionary of variable values to substitute

    Returns:
        Policy dictionary with variables substituted

    Raises:
        ValueError: If template_name is not found or required variables are missing
    """
    if variables is None:
        variables = {}
    return _render_template(template_name, variables)


__all__ = [
    "list_templates",
    "get_template_variables",
    "load_template",
]
