"""Declarative ``iam://`` resource specs, gated the same way tools are."""

from __future__ import annotations

import json

from fastmcp import Context

from iam_validator.mcp.component_spec import ResourceSpec
from iam_validator.mcp.context import get_check_catalog, get_check_details


async def checks_resource(ctx: Context | None = None) -> str:
    """List of all available validation checks.

    Each entry carries the check's id, description and class ``default_severity``
    plus the ``severity`` and ``enabled`` flag the current session config resolves
    to, so the catalog matches what validate_policy will actually run.
    """
    return json.dumps(get_check_catalog(ctx), indent=2)


async def sensitive_categories_resource() -> str:
    """Sensitive action categories and their descriptions.

    This resource describes the 4 categories of sensitive actions
    that the validator tracks.
    """
    from iam_validator.core.config.sensitive_actions import SENSITIVE_ACTION_CATEGORIES

    # Convert frozensets to lists for JSON serialization
    serializable = {
        category_id: {
            "name": data["name"],
            "description": data["description"],
            "severity": data["severity"],
            "action_count": len(data["actions"]),
        }
        for category_id, data in SENSITIVE_ACTION_CATEGORIES.items()
    }

    return json.dumps(serializable, indent=2)


async def sensitive_actions_resource(category: str) -> str:
    """List sensitive actions for a category (parameterized resource).

    Replaces the former ``list_sensitive_actions`` tool. Categories:
    credential_exposure, data_access, privilege_escalation, resource_exposure.
    """
    from iam_validator.mcp.tools.query import list_sensitive_actions

    actions = await list_sensitive_actions(category=category)
    return json.dumps({"category": category, "actions": actions}, indent=2)


async def check_details_resource(check_id: str, ctx: Context | None = None) -> str:
    """Per-check documentation (parameterized resource).

    Replaces the former ``get_check_details`` tool.
    """
    return json.dumps(get_check_details(check_id, ctx), indent=2)


def config_schema_resource() -> str:
    """JSON Schema for session configuration.

    Returns the schema for valid configuration settings,
    useful for AI assistants to validate config before setting.
    """
    from iam_validator.core.config.config_loader import SettingsSchema

    return json.dumps(SettingsSchema.model_json_schema(), indent=2)


def config_examples_resource() -> str:
    """Example configurations for common scenarios.

    Provides examples for different security postures and use cases.
    These configurations use the same format as the CLI validator YAML config.
    All validation is done by the IAM validator's built-in checks.
    """
    return """
# Configuration Examples

These configurations can be used with both the CLI (`--config`) and MCP server.
They control which checks run and their severity levels.

## 1. Enterprise Security (Strict)
Maximum security - all wildcards are critical, sensitive actions flagged.

```yaml
settings:
  fail_on_severity:
    - error
    - critical
    - high

# Make all wildcard checks critical severity
wildcard_action:
  enabled: true
  severity: critical

wildcard_resource:
  enabled: true
  severity: critical

full_wildcard:
  enabled: true
  severity: critical

service_wildcard:
  enabled: true
  severity: critical

# Flag all sensitive/privileged actions
sensitive_action:
  enabled: true
  severity: high

# Require conditions on sensitive actions
action_condition_enforcement:
  enabled: true
  severity: error
```

## 2. Development Environment (Permissive)
Relaxed settings for dev/sandbox - only catch critical issues.

```yaml
settings:
  fail_on_severity:
    - error
    - critical

# Disable sensitive action warnings in dev
sensitive_action:
  enabled: false

# Lower severity for wildcards (warn but don't fail)
wildcard_action:
  enabled: true
  severity: medium

wildcard_resource:
  enabled: true
  severity: medium

# Still catch full admin access
full_wildcard:
  enabled: true
  severity: critical
```

## 3. Compliance-Focused
Emphasizes policy structure and AWS validation.

```yaml
settings:
  fail_on_severity:
    - error
    - critical
    - high

# Ensure all actions are valid AWS actions
action_validation:
  enabled: true
  severity: error

# Validate condition keys and operators
condition_key_validation:
  enabled: true
  severity: error

condition_type_mismatch:
  enabled: true
  severity: error

# Ensure proper policy structure
policy_structure:
  enabled: true
  severity: error

# Check policy size limits
policy_size:
  enabled: true
  severity: error
```

## 4. Security Audit
Comprehensive security review - everything enabled at high severity.

```yaml
settings:
  fail_on_severity:
    - error
    - critical
    - high
    - medium

# All security checks at high severity
wildcard_action:
  enabled: true
  severity: high

wildcard_resource:
  enabled: true
  severity: high

full_wildcard:
  enabled: true
  severity: critical

service_wildcard:
  enabled: true
  severity: high

sensitive_action:
  enabled: true
  severity: high

action_condition_enforcement:
  enabled: true
  severity: high

# Catch NotAction/NotResource anti-patterns
not_action_not_resource:
  enabled: true
  severity: high
```

## 5. Minimal Validation
Quick validation - only structural and critical issues.

```yaml
settings:
  fail_on_severity:
    - error
    - critical
  parallel_execution: true

# Only critical checks
policy_structure:
  enabled: true
  severity: error

full_wildcard:
  enabled: true
  severity: critical

# Disable detailed checks for speed
action_validation:
  enabled: false

sensitive_action:
  enabled: false

condition_key_validation:
  enabled: false
```
"""


def workflow_examples_resource() -> str:
    """Detailed workflow examples for common IAM policy tasks.

    This resource contains step-by-step examples showing how to use
    the IAM Policy Validator tools effectively.
    """
    return """
# IAM Policy Validator - Workflow Examples

## Example 1: Create Policy from Template

USER: "I need a policy for Lambda to read from S3"

STEPS:
1. list_templates → found "lambda-s3-trigger"
2. ASK USER: "What's your S3 bucket name?"
3. generate_policy_from_template(
     template_name="lambda-s3-trigger",
     variables={"bucket_name": "user-bucket", "function_name": "my-func", ...}
   )
4. validate_policy on result
5. Present validated policy to user

## Example 2: Validate Overly Permissive Policy

USER: "Validate this policy: {Action: *, Resource: *}"

STEPS:
1. validate_policy → returns issues (wildcard_action, wildcard_resource)
2. fix_policy_issues → unfixed_issues shows wildcards can't be auto-fixed
3. RESPOND to user:
   "This policy grants full admin access. I need to know:
   - Which AWS service(s) do you need access to?
   - What operations (read/write/delete)?
   - Which specific resources (bucket names, table names, etc.)?"

## Example 3: Build Custom Policy

USER: "Create a policy to read DynamoDB table 'users' and write to S3 bucket 'backups'"

STEPS:
1. suggest_actions("read DynamoDB", "dynamodb") → get read actions
2. suggest_actions("write S3", "s3") → get write actions
3. build_minimal_policy(
     actions=["dynamodb:GetItem", "dynamodb:Query", "s3:PutObject"],
     resources=[
       "arn:aws:dynamodb:us-east-1:123456789012:table/users",
       "arn:aws:s3:::backups/*"
     ]
   )
4. validate_policy on result
5. Review security_notes and present to user

## Example 4: Fix Validation Issues

USER provides policy with issues

STEPS:
1. validate_policy → returns is_valid=false with issues
2. For each issue, read the `example` field - it shows the exact fix
3. fix_policy_issues → applies auto-fixes (Version, SIDs)
4. For remaining unfixed_issues:
   - If wildcard: ask user for specific actions/resources
   - If missing condition: use get_required_conditions to see what's needed
5. Re-validate until is_valid=true

## Example 5: Research Actions

USER: "What S3 write actions exist?"

STEPS:
1. query_service_actions(service="s3", access_level="write")
2. Present the list to user
3. If they pick actions, use check_sensitive_actions to warn about risks

## Example 6: Batch Validation

USER provides multiple policies to check

STEPS:
1. validate_policies_batch(policies=[...], verbose=False)
2. For each result, show policy_index and is_valid
3. Detail issues only for invalid policies
"""


RESOURCES: list[ResourceSpec] = [
    ResourceSpec(
        tag="validate",
        uri="iam://checks",
        name="checks_resource",
        fn=checks_resource,
    ),
    ResourceSpec(
        tag="validate",
        uri="iam://sensitive-categories",
        name="sensitive_categories_resource",
        fn=sensitive_categories_resource,
    ),
    ResourceSpec(
        tag="validate",
        uri="iam://sensitive-actions/{category}",
        name="sensitive_actions_resource",
        fn=sensitive_actions_resource,
    ),
    ResourceSpec(
        tag="validate",
        uri="iam://checks/{check_id}",
        name="check_details_resource",
        fn=check_details_resource,
    ),
    ResourceSpec(
        tag="orgconfig",
        uri="iam://config-schema",
        name="config_schema_resource",
        fn=config_schema_resource,
    ),
    ResourceSpec(
        tag="orgconfig",
        uri="iam://config-examples",
        name="config_examples_resource",
        fn=config_examples_resource,
    ),
    ResourceSpec(
        tag="validate",
        uri="iam://workflow-examples",
        name="workflow_examples_resource",
        fn=workflow_examples_resource,
    ),
]

__all__ = ["RESOURCES"]
