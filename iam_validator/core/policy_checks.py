"""IAM Policy Validation Module.

This module provides comprehensive validation of IAM policies including:
- Action validation against AWS Service Reference API
- Condition key validation
- Resource ARN format validation
- Security best practices checks
"""

import asyncio
import logging
import re
from pathlib import Path

from iam_validator.core.aws_fetcher import AWSServiceFetcher
from iam_validator.core.check_registry import CheckRegistry
from iam_validator.core.models import (
    IAMPolicy,
    PolicyType,
    PolicyValidationResult,
    Statement,
    ValidationIssue,
)

logger = logging.getLogger(__name__)


def _should_fail_on_issue(
    issue: ValidationIssue, fail_on_severities: list[str] | None = None
) -> bool:
    """Determine if an issue should cause validation to fail.

    Args:
        issue: Validation issue to check
        fail_on_severities: List of severity levels that should cause failure
                           Defaults to ["error"] if not specified

    Returns:
        True if the issue should cause validation to fail
    """
    if not fail_on_severities:
        fail_on_severities = ["error"]  # Default: only fail on errors

    # Check if issue severity is in the fail list
    return issue.severity in fail_on_severities


class PolicyValidator:
    """Validates IAM policies for correctness and security."""

    def __init__(self, fetcher: AWSServiceFetcher):
        """Initialize the validator.

        Args:
            fetcher: AWS service fetcher instance
        """
        self.fetcher = fetcher
        self._file_cache: dict[str, list[str]] = {}

    def _find_field_line(
        self, policy_file: str, statement_line: int, search_term: str
    ) -> int | None:
        """Find the specific line number for a field within a statement.

        Args:
            policy_file: Path to the policy file
            statement_line: Line number where the statement starts (Sid/first field line)
            search_term: The term to search for (e.g., action name, resource ARN)

        Returns:
            Line number where the field is found, or None
        """
        try:
            # Cache file contents
            if policy_file not in self._file_cache:
                with open(policy_file, encoding="utf-8") as f:
                    self._file_cache[policy_file] = f.readlines()

            lines = self._file_cache[policy_file]

            # Need to go back to find the opening brace of the statement
            # Look backwards from statement_line to find the opening {
            statement_start = statement_line
            for i in range(statement_line - 1, max(0, statement_line - 10), -1):
                if "{" in lines[i]:
                    statement_start = i + 1  # Convert to 1-indexed
                    break

            # Now search from the statement opening brace
            brace_depth = 0
            in_statement = False

            for i, line in enumerate(lines[statement_start - 1 :], start=statement_start):
                # Track braces to stay within statement bounds
                for char in line:
                    if char == "{":
                        brace_depth += 1
                        in_statement = True
                    elif char == "}":
                        brace_depth -= 1

                # Search for the term in this line
                if in_statement and search_term in line:
                    return i

                # Exit if we've left the statement
                if in_statement and brace_depth == 0:
                    break

            return None

        except Exception as e:
            logger.debug(f"Could not find field line in {policy_file}: {e}")
            return None

    async def validate_policy(
        self, policy: IAMPolicy, policy_file: str, policy_type: PolicyType = "IDENTITY_POLICY"
    ) -> PolicyValidationResult:
        """Validate a complete IAM policy.

        Args:
            policy: IAM policy to validate
            policy_file: Path to the policy file
            policy_type: Type of policy (IDENTITY_POLICY, RESOURCE_POLICY, SERVICE_CONTROL_POLICY)

        Returns:
            PolicyValidationResult with all findings
        """
        result = PolicyValidationResult(
            policy_file=policy_file, is_valid=True, policy_type=policy_type
        )

        # Apply automatic policy-type validation (not configurable - always runs)
        from iam_validator.checks import policy_type_validation

        policy_type_issues = await policy_type_validation.execute_policy(
            policy, policy_file, policy_type=policy_type
        )
        result.issues.extend(policy_type_issues)

        for idx, statement in enumerate(policy.statement):
            # Get line number for this statement
            statement_line = statement.line_number

            # Validate actions
            # Optimization: Batch actions by service and cache line lookups
            actions = statement.get_actions()
            non_wildcard_actions = [a for a in actions if a != "*"]

            # Group actions by service prefix for batch validation
            from collections import defaultdict

            actions_by_service = defaultdict(list)
            for action in non_wildcard_actions:
                if ":" in action:
                    service_prefix = action.split(":")[0]
                    actions_by_service[service_prefix].append(action)
                else:
                    # Invalid action format, validate individually
                    actions_by_service["_invalid"].append(action)

            # Pre-fetch all required services in parallel
            if actions_by_service:
                service_prefixes = [s for s in actions_by_service.keys() if s != "_invalid"]
                # Batch fetch services to warm up cache
                fetch_results = await asyncio.gather(
                    *[self.fetcher.fetch_service_by_name(s) for s in service_prefixes],
                    return_exceptions=True,  # Don't fail if a service doesn't exist
                )

                # Log any service fetch failures for debugging
                # Note: Individual action validation will still work and report proper errors
                for i, fetch_result in enumerate(fetch_results):
                    if isinstance(fetch_result, Exception):
                        service_name = service_prefixes[i]
                        logger.debug(
                            f"Pre-fetch failed for service '{service_name}': {fetch_result}. "
                            "Will validate actions individually."
                        )

            # Cache action line lookups to avoid repeated file searches
            action_line_cache = {}

            for action in non_wildcard_actions:
                # Look up line number once per action (cached)
                if action not in action_line_cache:
                    action_line = None
                    if statement_line:
                        # Search for the full action string in quotes to avoid partial matches
                        # Try full action first (e.g., "s3:GetObject")
                        action_line = self._find_field_line(
                            policy_file, statement_line, f'"{action}"'
                        )
                        # If not found, try just the action part after colon
                        if not action_line and ":" in action:
                            action_name = action.split(":")[-1]
                            action_line = self._find_field_line(
                                policy_file, statement_line, f'"{action_name}"'
                            )
                    action_line_cache[action] = action_line or statement_line

                await self._validate_action(
                    action,
                    idx,
                    statement.sid,
                    action_line_cache[action],
                    result,
                )

            # Validate condition keys if present
            # Optimization: Cache condition line lookups and batch validations
            if statement.condition:
                # Pre-filter non-wildcard actions once
                non_wildcard_actions = [a for a in actions if a != "*"]

                # Cache condition key line numbers to avoid repeated file searches
                condition_line_cache = {}

                for operator, conditions in statement.condition.items():
                    for condition_key in conditions.keys():
                        # Look up line number once per condition key
                        if condition_key not in condition_line_cache:
                            condition_line = None
                            if statement_line:
                                condition_line = self._find_field_line(
                                    policy_file, statement_line, condition_key
                                )
                            condition_line_cache[condition_key] = condition_line or statement_line

                        # Validate condition key against all non-wildcard actions
                        for action in non_wildcard_actions:
                            await self._validate_condition_key(
                                action,
                                condition_key,
                                idx,
                                statement.sid,
                                condition_line_cache[condition_key],
                                result,
                            )

            # Validate resources
            resources = statement.get_resources()
            for resource in resources:
                if resource != "*":  # Skip wildcard resources
                    # Try to find specific resource line
                    resource_line = None
                    if statement_line:
                        resource_line = self._find_field_line(policy_file, statement_line, resource)
                    self._validate_resource(
                        resource,
                        idx,
                        statement.sid,
                        resource_line or statement_line,
                        result,
                    )

            # Security best practice checks
            self._check_security_best_practices(statement, idx, statement_line, result, policy_file)

        # Update final validation status
        # Default to failing only on "error" severity for legacy validator
        result.is_valid = len([i for i in result.issues if _should_fail_on_issue(i)]) == 0

        return result

    async def _validate_action(
        self,
        action: str,
        statement_idx: int,
        statement_sid: str | None,
        line_number: int | None,
        result: PolicyValidationResult,
    ) -> None:
        """Validate a single action."""
        result.actions_checked += 1

        # Handle wildcard patterns like "s3:Get*"
        if "*" in action and action != "*":
            # Validate the service prefix exists
            try:
                service_prefix = action.split(":")[0]
                await self.fetcher.fetch_service_by_name(service_prefix)
                # For now, accept wildcard actions if service exists
                logger.debug(f"Wildcard action validated: {action}")
                return
            except Exception:
                result.issues.append(
                    ValidationIssue(
                        severity="warning",
                        statement_sid=statement_sid,
                        statement_index=statement_idx,
                        issue_type="wildcard_action",
                        message=f"Wildcard action '{action}' uses unverified service",
                        action=action,
                        suggestion="Consider being more specific with action permissions",
                        line_number=line_number,
                    )
                )
                return

        is_valid, error_msg, is_wildcard = await self.fetcher.validate_action(action)

        if not is_valid:
            result.issues.append(
                ValidationIssue(
                    severity="error",
                    statement_sid=statement_sid,
                    statement_index=statement_idx,
                    issue_type="invalid_action",
                    message=error_msg or f"Invalid action: {action}",
                    action=action,
                    line_number=line_number,
                )
            )

    async def _validate_condition_key(
        self,
        action: str,
        condition_key: str,
        statement_idx: int,
        statement_sid: str | None,
        line_number: int | None,
        result: PolicyValidationResult,
    ) -> None:
        """Validate a condition key against an action."""
        result.condition_keys_checked += 1

        is_valid, error_msg = await self.fetcher.validate_condition_key(action, condition_key)

        if not is_valid:
            result.issues.append(
                ValidationIssue(
                    severity="warning",
                    statement_sid=statement_sid,
                    statement_index=statement_idx,
                    issue_type="invalid_condition_key",
                    message=error_msg or f"Invalid condition key: {condition_key}",
                    action=action,
                    condition_key=condition_key,
                    line_number=line_number,
                )
            )

    def _validate_resource(
        self,
        resource: str,
        statement_idx: int,
        statement_sid: str | None,
        line_number: int | None,
        result: PolicyValidationResult,
    ) -> None:
        """Validate resource ARN format."""
        result.resources_checked += 1

        # Basic ARN format: arn:partition:service:region:account-id:resource-type/resource-id
        arn_pattern = r"^arn:(aws|aws-cn|aws-us-gov|aws-eusc|aws-iso|aws-iso-b|aws-iso-e|aws-iso-f):[a-z0-9\-]+:[a-z0-9\-]*:[0-9]*:.+$"

        if not re.match(arn_pattern, resource, re.IGNORECASE):
            result.issues.append(
                ValidationIssue(
                    severity="error",
                    statement_sid=statement_sid,
                    statement_index=statement_idx,
                    issue_type="invalid_resource",
                    message=f"Invalid ARN format: {resource}",
                    resource=resource,
                    suggestion="ARN should follow format: arn:partition:service:region:account-id:resource",
                    line_number=line_number,
                )
            )

    def _check_security_best_practices(
        self,
        statement: Statement,
        statement_idx: int,
        line_number: int | None,
        result: PolicyValidationResult,
        policy_file: str,
    ) -> None:
        """Check for security best practices."""

        # Check for overly permissive wildcards
        actions = statement.get_actions()
        resources = statement.get_resources()

        if statement.effect == "Allow":
            # Check for "*" in actions
            if "*" in actions:
                # Try to find "Action" field line
                action_field_line = None
                if line_number:
                    action_field_line = self._find_field_line(policy_file, line_number, '"Action"')
                result.issues.append(
                    ValidationIssue(
                        severity="warning",
                        statement_sid=statement.sid,
                        statement_index=statement_idx,
                        issue_type="overly_permissive",
                        message="Statement allows all actions (*)",
                        suggestion="Consider limiting to specific actions needed",
                        line_number=action_field_line or line_number,
                    )
                )

            # Check for "*" in resources
            if "*" in resources:
                # Try to find "Resource" field line
                resource_field_line = None
                if line_number:
                    resource_field_line = self._find_field_line(
                        policy_file, line_number, '"Resource"'
                    )
                result.issues.append(
                    ValidationIssue(
                        severity="warning",
                        statement_sid=statement.sid,
                        statement_index=statement_idx,
                        issue_type="overly_permissive",
                        message="Statement applies to all resources (*)",
                        suggestion="Consider limiting to specific resources",
                        line_number=resource_field_line or line_number,
                    )
                )

            # Check for both wildcards
            if "*" in actions and "*" in resources:
                result.issues.append(
                    ValidationIssue(
                        severity="error",
                        statement_sid=statement.sid,
                        statement_index=statement_idx,
                        issue_type="security_risk",
                        message="Statement allows all actions on all resources - CRITICAL SECURITY RISK",
                        suggestion="This grants full administrative access. Restrict to specific actions and resources.",
                        line_number=line_number,
                    )
                )

        # Check for missing conditions on sensitive actions
        sensitive_actions = [
            "iam:PassRole",
            "iam:CreateUser",
            "iam:CreateRole",
            "iam:PutUserPolicy",
            "iam:PutRolePolicy",
            "s3:DeleteBucket",
            "s3:PutBucketPolicy",
            "ec2:TerminateInstances",
        ]

        for action in actions:
            if action in sensitive_actions and not statement.condition:
                # Try to find specific action line
                action_line = None
                if line_number:
                    action_name = action.split(":")[-1] if ":" in action else action
                    action_line = self._find_field_line(policy_file, line_number, action_name)
                result.issues.append(
                    ValidationIssue(
                        severity="warning",
                        statement_sid=statement.sid,
                        statement_index=statement_idx,
                        issue_type="missing_condition",
                        message=f"Sensitive action '{action}' has no conditions",
                        action=action,
                        suggestion="Consider adding conditions to restrict when this action can be performed",
                        line_number=action_line or line_number,
                    )
                )


async def validate_policies(
    policies: list[tuple[str, IAMPolicy]],
    config_path: str | None = None,
    use_registry: bool = True,
    custom_checks_dir: str | None = None,
    policy_type: PolicyType = "IDENTITY_POLICY",
) -> list[PolicyValidationResult]:
    """Validate multiple policies concurrently.

    Args:
        policies: List of (file_path, policy) tuples
        config_path: Optional path to configuration file
        use_registry: If True, use CheckRegistry system; if False, use legacy validator
        custom_checks_dir: Optional path to directory containing custom checks for auto-discovery
        policy_type: Type of policy (IDENTITY_POLICY, RESOURCE_POLICY, SERVICE_CONTROL_POLICY)

    Returns:
        List of validation results
    """
    if not use_registry:
        # Legacy path - use old PolicyValidator
        # Load config for cache settings even in legacy mode
        from iam_validator.core.config.config_loader import ConfigLoader

        config = ConfigLoader.load_config(explicit_path=config_path, allow_missing=True)
        cache_enabled = config.get_setting("cache_enabled", True)
        cache_ttl_hours = config.get_setting("cache_ttl_hours", 168)
        cache_directory = config.get_setting("cache_directory", None)
        aws_services_dir = config.get_setting("aws_services_dir", None)
        cache_ttl_seconds = cache_ttl_hours * 3600

        async with AWSServiceFetcher(
            enable_cache=cache_enabled,
            cache_ttl=cache_ttl_seconds,
            cache_dir=cache_directory,
            aws_services_dir=aws_services_dir,
        ) as fetcher:
            validator = PolicyValidator(fetcher)

            tasks = [
                validator.validate_policy(policy, file_path, policy_type)
                for file_path, policy in policies
            ]

            results = await asyncio.gather(*tasks)

        return list(results)

    # New path - use CheckRegistry system
    from iam_validator.core.check_registry import create_default_registry
    from iam_validator.core.config.config_loader import ConfigLoader

    # Load configuration
    config = ConfigLoader.load_config(explicit_path=config_path, allow_missing=True)

    # Create registry with or without built-in checks based on configuration
    enable_parallel = config.get_setting("parallel_execution", True)
    enable_builtin_checks = config.get_setting("enable_builtin_checks", True)

    registry = create_default_registry(
        enable_parallel=enable_parallel, include_builtin_checks=enable_builtin_checks
    )

    if not enable_builtin_checks:
        logger.info("Built-in checks disabled - using only custom checks")

    # Apply configuration to built-in checks (if they were registered)
    if enable_builtin_checks:
        ConfigLoader.apply_config_to_registry(config, registry)

    # Load custom checks from explicit module paths (old method)
    custom_checks = ConfigLoader.load_custom_checks(config, registry)
    if custom_checks:
        logger.info(
            f"Loaded {len(custom_checks)} custom checks from modules: {', '.join(custom_checks)}"
        )

    # Auto-discover custom checks from directory (new method)
    # Priority: CLI arg > config file > default None
    checks_dir = custom_checks_dir or config.custom_checks_dir
    if checks_dir:
        checks_dir_path = Path(checks_dir).resolve()
        discovered_checks = ConfigLoader.discover_checks_in_directory(checks_dir_path, registry)
        if discovered_checks:
            logger.info(
                f"Auto-discovered {len(discovered_checks)} custom checks from {checks_dir_path}"
            )

    # Apply configuration again to include custom checks
    # This allows configuring auto-discovered checks via the config file
    ConfigLoader.apply_config_to_registry(config, registry)

    # Get fail_on_severity setting from config
    fail_on_severities = config.get_setting("fail_on_severity", ["error"])

    # Get cache settings from config
    cache_enabled = config.get_setting("cache_enabled", True)
    cache_ttl_hours = config.get_setting("cache_ttl_hours", 168)  # 7 days default
    cache_directory = config.get_setting("cache_directory", None)
    aws_services_dir = config.get_setting("aws_services_dir", None)
    cache_ttl_seconds = cache_ttl_hours * 3600

    # Validate policies using registry
    async with AWSServiceFetcher(
        enable_cache=cache_enabled,
        cache_ttl=cache_ttl_seconds,
        cache_dir=cache_directory,
        aws_services_dir=aws_services_dir,
    ) as fetcher:
        tasks = [
            _validate_policy_with_registry(
                policy, file_path, registry, fetcher, fail_on_severities, policy_type
            )
            for file_path, policy in policies
        ]

        results = await asyncio.gather(*tasks)

    return list(results)


async def _validate_policy_with_registry(
    policy: IAMPolicy,
    policy_file: str,
    registry: CheckRegistry,
    fetcher: AWSServiceFetcher,
    fail_on_severities: list[str] | None = None,
    policy_type: PolicyType = "IDENTITY_POLICY",
) -> PolicyValidationResult:
    """Validate a single policy using the CheckRegistry system.

    Args:
        policy: IAM policy to validate
        policy_file: Path to the policy file
        registry: CheckRegistry instance with configured checks
        fetcher: AWS service fetcher instance
        fail_on_severities: List of severity levels that should cause validation to fail
        policy_type: Type of policy (IDENTITY_POLICY, RESOURCE_POLICY, SERVICE_CONTROL_POLICY)

    Returns:
        PolicyValidationResult with all findings
    """
    result = PolicyValidationResult(policy_file=policy_file, is_valid=True, policy_type=policy_type)

    # Apply automatic policy-type validation (not configurable - always runs)
    from iam_validator.checks import policy_type_validation

    policy_type_issues = await policy_type_validation.execute_policy(
        policy, policy_file, policy_type=policy_type
    )
    result.issues.extend(policy_type_issues)

    # Run policy-level checks first (checks that need to see the entire policy)
    # These checks examine relationships between statements, not individual statements
    policy_level_issues = await registry.execute_policy_checks(
        policy, policy_file, fetcher, policy_type
    )
    result.issues.extend(policy_level_issues)

    # Execute all statement-level checks for each statement
    for idx, statement in enumerate(policy.statement):
        # Execute all registered checks in parallel (with ignore_patterns filtering)
        issues = await registry.execute_checks_parallel(statement, idx, fetcher, policy_file)

        # Add issues to result
        result.issues.extend(issues)

        # Update counters (approximate based on what was checked)
        actions = statement.get_actions()
        resources = statement.get_resources()

        result.actions_checked += len([a for a in actions if a != "*"])
        result.resources_checked += len([r for r in resources if r != "*"])

        # Count condition keys if present
        if statement.condition:
            for conditions in statement.condition.values():
                result.condition_keys_checked += len(conditions)

    # Update final validation status based on fail_on_severities configuration
    result.is_valid = (
        len([i for i in result.issues if _should_fail_on_issue(i, fail_on_severities)]) == 0
    )

    return result
