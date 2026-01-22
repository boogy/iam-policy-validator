"""Policy generation tools for MCP server.

This module provides MCP tools for generating IAM policies from templates,
explicit actions, and natural language descriptions. All generated policies
are validated and optionally enriched with security conditions.
"""

import asyncio
import functools
import re
from typing import Any

from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.config.category_suggestions import DEFAULT_CATEGORY_SUGGESTIONS
from iam_validator.core.config.check_documentation import CheckDocumentationRegistry
from iam_validator.core.config.sensitive_actions import SENSITIVE_ACTION_CATEGORIES
from iam_validator.mcp.models import GenerationResult, ValidationResult
from iam_validator.sdk import query_actions

# Pre-build action→category index at module load time for O(1) lookups
_ACTION_CATEGORY_INDEX: dict[str, str] = {}
for _category_id, _category_data in SENSITIVE_ACTION_CATEGORIES.items():
    for _action in _category_data["actions"]:
        _ACTION_CATEGORY_INDEX[_action] = _category_id

# Pre-compiled regex pattern cache for condition requirement matching
_COMPILED_PATTERNS: dict[str, re.Pattern[str]] = {}


def _get_category_for_action(action: str) -> str | None:
    """Get the category for a sensitive action using pre-built index.

    Args:
        action: AWS action name to check

    Returns:
        Category name if action is sensitive, None otherwise
    """
    return _ACTION_CATEGORY_INDEX.get(action)


def _get_compiled_pattern(pattern: str) -> re.Pattern[str]:
    """Get a compiled regex pattern, using cache for efficiency."""
    if pattern not in _COMPILED_PATTERNS:
        _COMPILED_PATTERNS[pattern] = re.compile(pattern)
    return _COMPILED_PATTERNS[pattern]


def _get_auto_conditions(actions: list[str]) -> tuple[dict[str, Any], list[str]]:
    """Get auto-applied conditions based on action requirements.

    Analyzes the actions list against CONDITION_REQUIREMENTS and returns
    conditions that should be automatically applied along with explanatory notes.

    Args:
        actions: List of AWS actions to analyze

    Returns:
        Tuple of (conditions_dict, notes_list) where:
            - conditions_dict: Dictionary of conditions to apply
            - notes_list: List of strings explaining what was auto-added
    """
    from iam_validator.core.config.condition_requirements import CONDITION_REQUIREMENTS

    auto_conditions: dict[str, Any] = {}
    notes: list[str] = []

    for action in actions:
        for requirement in CONDITION_REQUIREMENTS:
            # Check if this requirement applies to this action
            action_matches = False

            # Check direct action match
            if "actions" in requirement and action in requirement["actions"]:
                action_matches = True

            # Check pattern match using pre-compiled regex
            if not action_matches and "action_patterns" in requirement:
                for pattern in requirement["action_patterns"]:
                    if _get_compiled_pattern(pattern).match(action):
                        action_matches = True
                        break

            if not action_matches:
                continue

            # This requirement applies - extract conditions
            required_conditions = requirement.get("required_conditions", [])

            # Handle list of conditions (simple case)
            if isinstance(required_conditions, list):
                for cond in required_conditions:
                    condition_key = cond.get("condition_key")
                    expected_value = cond.get("expected_value")
                    description = cond.get("description", "")

                    if condition_key:
                        if expected_value is not None:
                            # We have a specific value - auto-add the condition
                            # Determine the operator based on value type
                            if isinstance(expected_value, bool):
                                operator = "Bool"
                                value = "true" if expected_value else "false"
                            elif isinstance(expected_value, str):
                                if expected_value.startswith("${"):
                                    # Policy variable - use StringEquals
                                    operator = "StringEquals"
                                    value = expected_value
                                else:
                                    operator = "StringEquals"
                                    value = expected_value
                            else:
                                # Default to StringEquals for other types
                                operator = "StringEquals"
                                value = str(expected_value)

                            # Add to auto_conditions
                            if operator not in auto_conditions:
                                auto_conditions[operator] = {}
                            auto_conditions[operator][condition_key] = value

                            # Add note
                            note_desc = (
                                description if description else f"Required for {condition_key}"
                            )
                            notes.append(f"Auto-added {condition_key} for {action}: {note_desc}")
                        else:
                            # No expected_value - add recommendation note only
                            note_desc = (
                                description if description else f"Consider adding {condition_key}"
                            )
                            notes.append(f"Recommendation for {action}: {note_desc}")

            # Handle complex conditions with any_of/none_of
            elif isinstance(required_conditions, dict):
                # For any_of, we apply the first option (most common pattern)
                if "any_of" in required_conditions:
                    options = required_conditions["any_of"]
                    if options:
                        # Apply the first option (typically the strongest control)
                        first_option = options[0]
                        condition_key = first_option.get("condition_key")
                        expected_value = first_option.get("expected_value")
                        description = first_option.get("description", "")

                        if condition_key and expected_value is not None:
                            # Determine operator
                            if isinstance(expected_value, bool):
                                operator = "Bool"
                                value = "true" if expected_value else "false"
                            elif isinstance(expected_value, str):
                                operator = "StringEquals"
                                value = expected_value
                            else:
                                operator = "StringEquals"
                                value = str(expected_value)

                            # Add to auto_conditions
                            if operator not in auto_conditions:
                                auto_conditions[operator] = {}
                            auto_conditions[operator][condition_key] = value

                            # Add note with "one of" context
                            notes.append(
                                f"Auto-added {condition_key} for {action} (one of {len(options)} options): {description}"
                            )

                # For none_of, we skip auto-adding (validation will catch violations)
                # These are negative conditions that prevent bad configs

    return auto_conditions, notes


async def generate_policy_from_template(
    template_name: str,
    variables: dict[str, str],
    config_path: str | None = None,
) -> GenerationResult:
    """Generate an IAM policy from a built-in template.

    This tool loads a pre-defined policy template, substitutes the provided
    variables, and validates the generated policy using the IAM validator's
    built-in checks. Any security issues are reported through validation results.

    Args:
        template_name: Name of the template to use. Available templates:
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
        variables: Dictionary of variable values to substitute in the template.
            Required variables depend on the template (see list_templates).
        config_path: Optional path to YAML configuration file for validation.
            Uses the same config format as the CLI validator.

    Returns:
        GenerationResult with:
            - policy: The generated IAM policy
            - validation: Validation results from built-in checks
            - security_notes: Security warnings from validation
            - template_used: Name of the template used

    Raises:
        ValueError: If template not found or required variables missing

    Example:
        >>> result = await generate_policy_from_template(
        ...     template_name="s3-read-only",
        ...     variables={"bucket_name": "my-data", "prefix": "logs/"}
        ... )
        >>> print(result.policy)
    """
    from iam_validator.mcp.templates import load_template
    from iam_validator.mcp.tools.validation import validate_policy

    # Load and substitute template
    policy = load_template(template_name, variables)

    # Validate the generated policy using the validator's built-in checks
    validation_result = await validate_policy(
        policy=policy,
        policy_type="identity",
        config_path=config_path,
        use_org_config=False,  # Config is passed explicitly via config_path
    )

    # Extract security notes from validation issues
    security_notes: list[str] = []
    for issue in validation_result.issues:
        if issue.severity in ("high", "critical", "error"):
            security_notes.append(f"{issue.severity.upper()}: {issue.message}")

    return GenerationResult(
        policy=policy,
        validation=ValidationResult(
            is_valid=validation_result.is_valid,
            issues=validation_result.issues,
            policy_file=validation_result.policy_file,
        ),
        security_notes=security_notes,
        template_used=template_name,
    )


async def build_minimal_policy(
    actions: list[str],
    resources: list[str],
    conditions: dict[str, Any] | None = None,
    config_path: str | None = None,
    fetcher: AWSServiceFetcher | None = None,
) -> GenerationResult:
    """Build a minimal IAM policy from explicit actions and resources.

    This tool constructs a policy statement from the provided actions and resources.
    It validates that actions exist in AWS, checks for sensitive actions, and
    validates the generated policy using the validator's built-in checks.

    Args:
        actions: List of AWS actions to allow (e.g., ["s3:GetObject", "s3:ListBucket"])
        resources: List of resource ARNs (e.g., ["arn:aws:s3:::my-bucket/*"])
        conditions: Optional conditions to add to the statement
        config_path: Optional path to YAML configuration file for validation.
            Uses the same config format as the CLI validator.
        fetcher: Optional shared AWSServiceFetcher instance. If None, creates a new one.

    Returns:
        GenerationResult with:
            - policy: The generated IAM policy
            - validation: Validation results from built-in checks
            - security_notes: Security warnings from validation

    Example:
        >>> result = await build_minimal_policy(
        ...     actions=["s3:GetObject", "s3:ListBucket"],
        ...     resources=["arn:aws:s3:::my-bucket", "arn:aws:s3:::my-bucket/*"]
        ... )
        >>> print(result.policy)
    """
    from iam_validator.core.models import ValidationIssue

    security_notes: list[str] = []
    effective_conditions = conditions.copy() if conditions else {}

    # Use provided fetcher or create a new one
    if fetcher is not None:
        # Use shared fetcher directly (no context manager)
        _fetcher = fetcher
        should_close = False
    else:
        # Create new fetcher with context manager
        _fetcher = AWSServiceFetcher()
        await _fetcher.__aenter__()
        should_close = True

    try:
        # Separate wildcard and exact actions for validation
        wildcard_actions = []
        exact_actions = []
        for action in actions:
            if "*" in action:
                if action == "*":
                    # Block bare wildcard
                    return GenerationResult(
                        policy={},
                        validation=ValidationResult(
                            is_valid=False,
                            issues=[
                                ValidationIssue(
                                    severity="error",
                                    statement_index=0,
                                    issue_type="bare_wildcard_not_allowed",
                                    message="Action: '*' is not allowed in generated policies",
                                    suggestion="Specify explicit actions instead of using wildcard",
                                    check_id="policy_generation",
                                )
                            ],
                            policy_file="generated-policy",
                        ),
                        security_notes=["Policy generation blocked: bare wildcard action detected"],
                    )
                wildcard_actions.append(action)
            else:
                exact_actions.append(action)

        # Validate wildcard actions (must be done individually - expand each)
        for action in wildcard_actions:
            try:
                await _fetcher.expand_wildcard_action(action)
            except Exception:
                # Invalid wildcard
                return GenerationResult(
                    policy={},
                    validation=ValidationResult(
                        is_valid=False,
                        issues=[
                            ValidationIssue(
                                severity="error",
                                statement_index=0,
                                issue_type="invalid_wildcard_action",
                                message=f"Wildcard action '{action}' cannot be expanded to valid actions",
                                suggestion="Verify the action pattern is correct",
                                check_id="policy_generation",
                            )
                        ],
                        policy_file="generated-policy",
                    ),
                    security_notes=[],
                )

        # Batch validate exact actions (more efficient - fetches each service once)
        if exact_actions:
            validation_results = await _fetcher.validate_actions_batch(exact_actions)
            for action, (is_valid, error, _) in validation_results.items():
                if not is_valid:
                    return GenerationResult(
                        policy={},
                        validation=ValidationResult(
                            is_valid=False,
                            issues=[
                                ValidationIssue(
                                    severity="error",
                                    statement_index=0,
                                    issue_type="invalid_action",
                                    message=f"Action '{action}' is not valid: {error}",
                                    suggestion="Verify the action name is correct",
                                    check_id="policy_generation",
                                )
                            ],
                            policy_file="generated-policy",
                        ),
                        security_notes=[],
                    )

        # Check for bare Resource: "*" with write actions
        if "*" in resources:
            # Check if any actions are write-level
            has_write_actions = False
            for action in actions:
                if "*" not in action:
                    try:
                        # Check access level
                        service = action.split(":")[0]
                        action_list = await query_actions(_fetcher, service, access_level="write")
                        if any(a["action"] == action for a in action_list):
                            has_write_actions = True
                            break
                    except Exception:
                        pass

            if has_write_actions:
                return GenerationResult(
                    policy={},
                    validation=ValidationResult(
                        is_valid=False,
                        issues=[
                            ValidationIssue(
                                severity="error",
                                statement_index=0,
                                issue_type="bare_wildcard_resource_not_allowed",
                                message="Resource: '*' with write actions is not allowed",
                                suggestion="Specify explicit resource ARNs instead of using wildcard",
                                check_id="policy_generation",
                            )
                        ],
                        policy_file="generated-policy",
                    ),
                    security_notes=[
                        "Policy generation blocked: bare wildcard resource with write actions"
                    ],
                )

        # Check for sensitive actions and add warnings
        sensitive_action_notes: list[dict[str, Any]] = []
        for action in actions:
            if "*" not in action:
                category = _get_category_for_action(action)
                if category:
                    category_data = SENSITIVE_ACTION_CATEGORIES[category]
                    sensitive_action_notes.append(
                        {
                            "action": action,
                            "category": category,
                            "severity": category_data["severity"],
                            "description": category_data["description"],
                        }
                    )
                    security_notes.append(
                        f"Warning: '{action}' is a sensitive action ({category_data['name']})"
                    )

        # Auto-add required conditions based on CONDITION_REQUIREMENTS
        auto_conditions, auto_notes = _get_auto_conditions(actions)
        if auto_conditions:
            # Merge auto-conditions into effective_conditions
            from iam_validator.mcp.session_config import merge_conditions

            effective_conditions = merge_conditions(effective_conditions, auto_conditions)
            # Add notes about what was auto-added
            security_notes.extend(auto_notes)

        # Group actions by service for cleaner policy structure
        actions_by_service: dict[str, list[str]] = {}
        for action in actions:
            service = action.split(":")[0]
            if service not in actions_by_service:
                actions_by_service[service] = []
            actions_by_service[service].append(action)

        # Build the policy
        statement: dict[str, Any] = {
            "Sid": "GeneratedPolicy",
            "Effect": "Allow",
            "Action": sorted(actions),  # Keep all actions in one statement for now
            "Resource": resources if isinstance(resources, list) else [resources],
        }

        # Add conditions if provided or auto-generated
        if effective_conditions:
            statement["Condition"] = effective_conditions

        policy: dict[str, Any] = {
            "Version": "2012-10-17",
            "Statement": [statement],
        }

        # Validate the generated policy using the validator's built-in checks
        from iam_validator.mcp.tools.validation import validate_policy

        validation_result = await validate_policy(
            policy=policy,
            policy_type="identity",
            config_path=config_path,
            use_org_config=False,  # Config is passed explicitly via config_path
        )

        # Add high-severity issues to security notes
        for issue in validation_result.issues:
            if issue.severity in ("high", "critical", "error"):
                security_notes.append(f"{issue.severity.upper()}: {issue.message}")

        return GenerationResult(
            policy=policy,
            validation=ValidationResult(
                is_valid=validation_result.is_valid,
                issues=validation_result.issues,
                policy_file=validation_result.policy_file,
            ),
            security_notes=security_notes,
        )
    finally:
        # Clean up fetcher if we created it
        if should_close:
            await _fetcher.__aexit__(None, None, None)


@functools.lru_cache(maxsize=1)
def _get_cached_templates() -> tuple[dict[str, Any], ...]:
    """Build template list once, return tuple for immutability.

    This helper is cached with lru_cache to avoid rebuilding
    the template list on every call to list_templates().

    Returns:
        Tuple of template dictionaries (immutable for caching)
    """
    from iam_validator.mcp.templates.builtin import (
        list_templates as get_templates_metadata,
    )

    templates_metadata = get_templates_metadata()
    return tuple(
        {
            "name": tmpl["name"],
            "description": tmpl["description"],
            "variables": [
                {
                    "name": var["name"],
                    "description": var["description"],
                    "required": var.get("required", True),
                }
                for var in tmpl["variables"]
            ],
        }
        for tmpl in templates_metadata
    )


async def list_templates() -> list[dict[str, Any]]:
    """List all available policy templates with their metadata.

    Returns:
        List of template dictionaries, each containing:
            - name: Template identifier (use with generate_policy_from_template)
            - description: Human-readable description
            - variables: List of variable objects with:
                - name: Variable name to use in the variables dict
                - description: What value to provide
                - required: Whether the variable is required

    Example:
        >>> templates = await list_templates()
        >>> for tmpl in templates:
        ...     print(f"{tmpl['name']}: {tmpl['description']}")
        ...     for var in tmpl['variables']:
        ...         print(f"  - {var['name']}: {var['description']}")
    """
    return list(_get_cached_templates())


async def suggest_actions(
    description: str, service: str | None = None, fetcher: AWSServiceFetcher | None = None
) -> list[str]:
    """Suggest AWS actions based on a natural language description.

    This tool uses keyword pattern matching to suggest appropriate AWS actions
    based on the task description. It's useful for discovering actions when
    building policies from scratch.

    Args:
        description: Natural language description of the desired permissions
            (e.g., "read files from S3", "invoke Lambda functions")
        service: Optional AWS service to limit suggestions to (e.g., "s3", "lambda")
        fetcher: Optional shared AWSServiceFetcher instance. If None, creates a new one.

    Returns:
        List of suggested action names

    Example:
        >>> actions = await suggest_actions("read and write DynamoDB tables", "dynamodb")
        >>> print(actions)
        ['dynamodb:GetItem', 'dynamodb:PutItem', 'dynamodb:UpdateItem', ...]
    """
    description_lower = description.lower()

    # Keyword mapping for access levels
    access_level_keywords = {
        "read": ["read", "get", "describe", "view", "download", "retrieve", "fetch"],
        "write": [
            "write",
            "put",
            "create",
            "update",
            "modify",
            "upload",
            "edit",
            "change",
        ],
        "list": ["list", "enumerate", "browse", "search", "query", "scan"],
        "tagging": ["tag", "untag", "label"],
        "permissions-management": [
            "permission",
            "policy",
            "grant",
            "revoke",
            "attach",
            "detach",
        ],
    }

    # Determine which access levels match the description
    matched_access_levels = []
    for access_level, keywords in access_level_keywords.items():
        if any(keyword in description_lower for keyword in keywords):
            matched_access_levels.append(access_level)

    # If no specific access level matched, default to read + list
    if not matched_access_levels:
        matched_access_levels = ["read", "list"]

    # Service detection from description if not provided
    if service is None:
        service_keywords = {
            "s3": ["s3", "bucket", "object", "file", "storage"],
            "lambda": ["lambda", "function", "invoke"],
            "dynamodb": ["dynamodb", "table", "item", "nosql"],
            "ec2": ["ec2", "instance", "vm", "virtual machine"],
            "iam": ["iam", "user", "role", "permission", "policy"],
            "cloudwatch": ["cloudwatch", "log", "metric", "monitoring"],
            "secretsmanager": ["secret", "credential", "password"],
            "kms": ["kms", "encrypt", "decrypt", "key"],
            "rds": ["rds", "database", "db", "sql"],
            "sns": ["sns", "notification", "topic", "publish"],
            "sqs": ["sqs", "queue", "message"],
        }

        for svc, keywords in service_keywords.items():
            if any(keyword in description_lower for keyword in keywords):
                service = svc
                break

    if service is None:
        # No service detected, return empty list
        return []

    # Use provided fetcher or create a new one
    if fetcher is not None:
        # Use shared fetcher directly
        _fetcher = fetcher
        should_close = False
    else:
        # Create new fetcher with context manager
        _fetcher = AWSServiceFetcher()
        await _fetcher.__aenter__()
        should_close = True

    try:
        # Query all access levels in parallel for better performance
        async def query_level(level: str) -> list[str]:
            try:
                actions = await query_actions(
                    _fetcher,
                    service,
                    access_level=level,  # type: ignore
                )
                return [a["action"] for a in actions]
            except Exception:
                # Service might not exist or other error
                return []

        results = await asyncio.gather(*[query_level(level) for level in matched_access_levels])
        # Flatten results and deduplicate using a set
        suggested_actions: set[str] = set()
        for result in results:
            suggested_actions.update(result)
    finally:
        # Clean up fetcher if we created it
        if should_close:
            await _fetcher.__aexit__(None, None, None)

    # Return sorted list
    return sorted(suggested_actions)


async def get_required_conditions(actions: list[str]) -> dict[str, Any]:
    """Get the conditions required for a list of actions.

    This tool looks up condition requirements from the IAM Policy Validator's
    configuration and returns the requirements for the given actions.

    Args:
        actions: List of AWS actions to analyze

    Returns:
        Dictionary with:
            - requirements: List of condition requirements from the validator config
            - actions_matched: Which actions matched requirements
            - summary: Human-readable summary of what conditions are needed

    Example:
        >>> conditions = await get_required_conditions(["iam:PassRole", "s3:GetObject"])
        >>> print(conditions["summary"])
    """
    from iam_validator.core.config.condition_requirements import CONDITION_REQUIREMENTS

    matched_requirements: list[dict[str, Any]] = []
    actions_matched: list[str] = []

    for action in actions:
        for requirement in CONDITION_REQUIREMENTS:
            # Check direct action match
            if "actions" in requirement and action in requirement["actions"]:
                matched_requirements.append(requirement)
                actions_matched.append(action)
                break

            # Check pattern match
            if "action_patterns" in requirement:
                for pattern in requirement["action_patterns"]:
                    if re.match(pattern, action):
                        matched_requirements.append(requirement)
                        actions_matched.append(action)
                        break

    # Build a summary
    summary_parts = []
    for req in matched_requirements:
        if "suggestion_text" in req:
            summary_parts.append(req["suggestion_text"])

    return {
        "requirements": matched_requirements,
        "actions_matched": list(set(actions_matched)),
        "summary": "\n\n".join(summary_parts)
        if summary_parts
        else "No specific condition requirements found for these actions.",
    }


def _get_remediation_from_validator(action: str, category: str) -> dict[str, Any]:
    """Get remediation guidance for a sensitive action from the validator's data.

    Uses the IAM validator's category_suggestions module for ABAC-focused
    remediation guidance, and CheckDocumentationRegistry for general check documentation.

    Args:
        action: AWS action name
        category: Risk category (credential_exposure, data_access, priv_esc, resource_exposure)

    Returns:
        Dictionary with remediation guidance from the validator
    """
    # Get category suggestions from validator (ABAC-focused guidance)
    category_suggestions = DEFAULT_CATEGORY_SUGGESTIONS.get(category, {})

    # Check for action-specific override first
    action_overrides = category_suggestions.get("action_overrides", {})
    if action in action_overrides:
        override = action_overrides[action]
        suggestion = override.get("suggestion", "")
        example = override.get("example", "")
    else:
        # Fall back to category-level guidance
        suggestion = category_suggestions.get("suggestion", "")
        example = category_suggestions.get("example", "")

    # Get check documentation from the validator's registry
    check_doc = CheckDocumentationRegistry.get("sensitive_action")
    remediation_steps = check_doc.remediation_steps if check_doc else []
    documentation_url = check_doc.documentation_url if check_doc else None
    risk_explanation = check_doc.risk_explanation if check_doc else None

    # Determine risk level from category severity
    category_data = SENSITIVE_ACTION_CATEGORIES.get(category, {})
    risk_level = "CRITICAL" if category_data.get("severity") == "critical" else "HIGH"

    return {
        "risk_level": risk_level,
        "suggestion": suggestion,
        "condition_example": example,
        "remediation_steps": remediation_steps,
        "documentation_url": documentation_url,
        "risk_explanation": risk_explanation,
    }


async def check_sensitive_actions(actions: list[str]) -> dict[str, Any]:
    """Check if any actions in the list are sensitive and get remediation guidance.

    This tool analyzes actions against the IAM Policy Validator's sensitive
    actions catalog and returns remediation guidance sourced directly from
    the validator's configuration.

    The sensitive actions catalog contains 490+ actions across 4 categories,
    sourced from https://github.com/primeharbor/sensitive_iam_actions

    IMPORTANT FOR AI CLIENTS: To fix sensitive action findings:
    1. Add the suggested IAM conditions to your policy statement
    2. The condition_example field contains ready-to-use JSON
    3. After adding conditions, re-validate to confirm the fix
    4. If issues persist, the action may need additional restrictions

    Args:
        actions: List of AWS actions to check

    Returns:
        Dictionary containing:
            - sensitive_actions: List of sensitive actions with remediation
                - action: The action name
                - category: Risk category
                - severity: critical or high
                - description: Category description
                - remediation: Guidance from the IAM validator including:
                    - risk_level: CRITICAL or HIGH
                    - suggestion: ABAC-focused guidance on what conditions to add
                    - condition_example: Ready-to-use JSON condition block
                    - remediation_steps: Step-by-step fix guidance
                    - documentation_url: AWS documentation link
            - total_checked: Number of actions checked
            - sensitive_count: Number of sensitive actions found
            - categories_found: List of unique risk categories
            - has_critical: Whether any CRITICAL actions were found
            - summary: Quick summary with key recommendations
            - fix_guidance: Clear instructions for AI clients on how to resolve

    Example:
        >>> result = await check_sensitive_actions(["iam:PassRole", "s3:GetObject"])
        >>> for item in result["sensitive_actions"]:
        ...     print(f"Action: {item['action']}")
        ...     print(f"Fix: Add this condition block:")
        ...     print(item['remediation']['condition_example'])
    """
    sensitive_actions_found: list[dict[str, Any]] = []
    categories_found: set[str] = set()
    has_critical = False

    for action in actions:
        category = _get_category_for_action(action)
        if category:
            category_data = SENSITIVE_ACTION_CATEGORIES[category]
            categories_found.add(category)

            if category_data["severity"] == "critical":
                has_critical = True

            # Get remediation from validator's data (not duplicated logic)
            remediation = _get_remediation_from_validator(action, category)

            sensitive_actions_found.append(
                {
                    "action": action,
                    "category": category,
                    "severity": category_data["severity"],
                    "description": category_data["description"],
                    "remediation": remediation,
                }
            )

    # Generate summary with actionable guidance
    summary = ""
    fix_guidance = ""
    if sensitive_actions_found:
        summary = f"Found {len(sensitive_actions_found)} sensitive action(s). "
        if has_critical:
            summary += "CRITICAL actions detected - require MFA and strict conditions. "
        if "credential_exposure" in categories_found:
            summary += "Credential exposure risk present. "
        if "priv_esc" in categories_found:
            summary += "Privilege escalation risk present. "

        # Clear fix guidance for AI clients to prevent loops
        fix_guidance = (
            "To resolve these findings:\n"
            "1. Add IAM conditions to each statement containing sensitive actions\n"
            "2. Use the condition_example from each finding as a starting point\n"
            "3. Customize placeholder values (e.g., replace IP ranges, tag values)\n"
            "4. Re-validate the policy after adding conditions\n"
            "5. If the same action is still flagged, the validator's sensitive_action "
            "check may require specific conditions - see the suggestion field for details"
        )
    else:
        summary = "No sensitive actions detected."
        fix_guidance = "No action required - no sensitive actions found in the provided list."

    return {
        "sensitive_actions": sensitive_actions_found,
        "total_checked": len(actions),
        "sensitive_count": len(sensitive_actions_found),
        "categories_found": sorted(categories_found),
        "has_critical": has_critical,
        "summary": summary,
        "fix_guidance": fix_guidance,
    }
