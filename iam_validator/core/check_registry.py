"""
Check Registry for IAM Policy Validator.

This module provides a pluggable check system that allows:
1. Registering built-in and custom checks
2. Enabling/disabling checks via configuration
3. Configuring check behavior
4. Easy extension without modifying core code
5. Parallel execution of checks for performance
"""

import asyncio
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from iam_validator.core.aws_fetcher import AWSServiceFetcher
from iam_validator.core.ignore_patterns import IgnorePatternMatcher
from iam_validator.core.models import Statement, ValidationIssue

if TYPE_CHECKING:
    from iam_validator.core.models import IAMPolicy


@dataclass
class CheckConfig:
    """Configuration for a single check."""

    check_id: str
    enabled: bool = True
    severity: str | None = None  # Override default severity
    config: dict[str, Any] = field(default_factory=dict)  # Check-specific config
    description: str = ""
    root_config: dict[str, Any] = field(default_factory=dict)  # Full config for cross-check access
    ignore_patterns: list[dict[str, Any]] = field(default_factory=list)  # NEW: Ignore patterns
    """
    List of patterns to ignore findings.

    Each pattern is a dict with optional fields:
    - filepath: Regex to match file path
    - action: Regex to match action name
    - resource: Regex to match resource
    - sid: Exact SID to match (or regex if ends with .*)
    - condition_key: Regex to match condition key

    Multiple fields in one pattern = AND logic
    Multiple patterns = OR logic (any pattern matches → ignore)

    Example:
        ignore_patterns:
          - filepath: "test/.*|examples/.*"
          - filepath: "policies/readonly-.*"
            action: ".*:(Get|List|Describe).*"
          - sid: "AllowReadOnlyAccess"
    """

    def should_ignore(self, issue: ValidationIssue, filepath: str = "") -> bool:
        """
        Check if issue should be ignored based on ignore patterns.

        Uses centralized IgnorePatternMatcher for high-performance filtering
        with cached compiled regex patterns.

        Args:
            issue: The validation issue to check
            filepath: Path to the policy file

        Returns:
            True if the issue should be ignored

        Performance:
            - Cached regex compilation (LRU cache)
            - Early exit optimization
        """
        return IgnorePatternMatcher.should_ignore_issue(issue, filepath, self.ignore_patterns)

    def filter_actions(self, actions: frozenset[str]) -> frozenset[str]:
        """
        Filter actions based on action ignore patterns.

        Uses centralized IgnorePatternMatcher for high-performance filtering
        with cached compiled regex patterns.

        This is useful for checks that need to filter a set of actions before
        creating ValidationIssues (e.g., sensitive_action check).

        Args:
            actions: Set of actions to filter

        Returns:
            Filtered set of actions (actions matching ignore patterns removed)

        Performance:
            - Cached regex compilation (LRU cache)
            - Early exit per action on first match
        """
        return IgnorePatternMatcher.filter_actions(actions, self.ignore_patterns)


class PolicyCheck(ABC):
    """
    Base class for all policy checks.

    To create a custom check:
    1. Inherit from this class
    2. Implement check_id, description, and execute()
    3. Register with CheckRegistry

    Example:
        class MyCustomCheck(PolicyCheck):
            check_id = "my_custom_check"
            description = "Validates custom compliance rules"

            async def execute(self, statement, statement_idx, fetcher, config):
                issues = []
                # Your validation logic here
                return issues
    """

    @property
    @abstractmethod
    def check_id(self) -> str:
        """Unique identifier for this check (e.g., 'action_validation')."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Human-readable description of what this check does."""
        pass

    @property
    def default_severity(self) -> str:
        """Default severity level for issues found by this check."""
        return "warning"

    @abstractmethod
    async def execute(
        self,
        statement: Statement,
        statement_idx: int,
        fetcher: AWSServiceFetcher,
        config: CheckConfig,
    ) -> list[ValidationIssue]:
        """
        Execute the check on a policy statement.

        Args:
            statement: The IAM policy statement to check
            statement_idx: Index of the statement in the policy
            fetcher: AWS service fetcher for validation against AWS APIs
            config: Configuration for this check instance

        Returns:
            List of ValidationIssue objects found by this check
        """
        pass

    async def execute_policy(
        self,
        policy: "IAMPolicy",
        policy_file: str,
        fetcher: AWSServiceFetcher,
        config: CheckConfig,
        **kwargs,
    ) -> list[ValidationIssue]:
        """
        Execute the check on the entire policy (optional method).

        This method is for checks that need to examine all statements together,
        such as checking for duplicate SIDs or cross-statement relationships.

        By default, this returns an empty list. Override this method if your
        check needs access to the full policy.

        Args:
            policy: The complete IAM policy to check
            policy_file: Path to the policy file (for context/reporting)
            fetcher: AWS service fetcher for validation against AWS APIs
            config: Configuration for this check instance
            **kwargs: Additional context (policy_type, etc.)

        Returns:
            List of ValidationIssue objects found by this check
        """
        del policy, policy_file, fetcher, config  # Unused in default implementation
        return []

    def get_severity(self, config: CheckConfig) -> str:
        """Get the severity level, respecting config overrides."""
        return config.severity or self.default_severity

    def is_policy_level_check(self) -> bool:
        """
        Check if this is a policy-level check.

        Returns True if the check overrides execute_policy() method.
        This helps the registry know whether to call execute_policy() or execute().
        """
        # Check if execute_policy has been overridden from the base class
        return type(self).execute_policy is not PolicyCheck.execute_policy


class CheckRegistry:
    """
    Registry for managing validation checks.

    Supports parallel execution of checks for improved performance.

    Usage:
        registry = CheckRegistry()
        registry.register(ActionValidationCheck())
        registry.register(MyCustomCheck())

        # Get all enabled checks
        checks = registry.get_enabled_checks()

        # Configure checks
        registry.configure_check('action_validation', CheckConfig(
            check_id='action_validation',
            enabled=True,
            severity='error'
        ))

        # Execute checks in parallel
        issues = await registry.execute_checks_parallel(statement, idx, fetcher)
    """

    def __init__(self, enable_parallel: bool = True):
        """
        Initialize the registry.

        Args:
            enable_parallel: If True, execute checks in parallel (default: True)
        """
        self._checks: dict[str, PolicyCheck] = {}
        self._configs: dict[str, CheckConfig] = {}
        self.enable_parallel = enable_parallel

    def register(self, check: PolicyCheck) -> None:
        """
        Register a new check.

        Args:
            check: PolicyCheck instance to register
        """
        self._checks[check.check_id] = check

        # Create default config if not exists
        if check.check_id not in self._configs:
            self._configs[check.check_id] = CheckConfig(
                check_id=check.check_id,
                enabled=True,
                description=check.description,
            )

    def unregister(self, check_id: str) -> None:
        """
        Unregister a check by ID.

        Args:
            check_id: ID of the check to unregister
        """
        if check_id in self._checks:
            del self._checks[check_id]
        if check_id in self._configs:
            del self._configs[check_id]

    def configure_check(self, check_id: str, config: CheckConfig) -> None:
        """
        Configure a registered check.

        Args:
            check_id: ID of the check to configure
            config: Configuration to apply
        """
        if check_id not in self._checks:
            raise ValueError(f"Check '{check_id}' is not registered")
        self._configs[check_id] = config

    def get_all_checks(self) -> list[PolicyCheck]:
        """Get all registered checks (enabled and disabled)."""
        return list(self._checks.values())

    def get_enabled_checks(self) -> list[PolicyCheck]:
        """Get only enabled checks."""
        return [
            check
            for check_id, check in self._checks.items()
            if self._configs.get(check_id, CheckConfig(check_id=check_id)).enabled
        ]

    def get_check(self, check_id: str) -> PolicyCheck | None:
        """Get a specific check by ID."""
        return self._checks.get(check_id)

    def get_config(self, check_id: str) -> CheckConfig | None:
        """Get configuration for a specific check."""
        return self._configs.get(check_id)

    def is_enabled(self, check_id: str) -> bool:
        """Check if a specific check is enabled."""
        config = self._configs.get(check_id)
        return config.enabled if config else False

    def list_checks(self) -> list[dict[str, Any]]:
        """
        List all checks with their status and description.

        Returns:
            List of dicts with check information
        """
        result = []
        for check_id, check in self._checks.items():
            config = self._configs.get(check_id, CheckConfig(check_id=check_id))
            result.append(
                {
                    "check_id": check_id,
                    "description": check.description,
                    "enabled": config.enabled,
                    "severity": config.severity or check.default_severity,
                }
            )
        return result

    async def execute_checks_parallel(
        self,
        statement: Statement,
        statement_idx: int,
        fetcher: AWSServiceFetcher,
        filepath: str = "",
    ) -> list[ValidationIssue]:
        """
        Execute all enabled checks in parallel for maximum performance.

        This method runs all enabled checks concurrently using asyncio.gather(),
        which can significantly speed up validation when multiple checks are enabled.

        Args:
            statement: The IAM policy statement to validate
            statement_idx: Index of the statement in the policy
            fetcher: AWS service fetcher for API calls
            filepath: Path to the policy file (for ignore_patterns filtering)

        Returns:
            List of all ValidationIssue objects from all checks (filtered by ignore_patterns)
        """
        enabled_checks = self.get_enabled_checks()

        if not enabled_checks:
            return []

        if not self.enable_parallel or len(enabled_checks) == 1:
            # Run sequentially if parallel disabled or only one check
            all_issues = []
            for check in enabled_checks:
                config = self.get_config(check.check_id)
                if config:
                    issues = await check.execute(statement, statement_idx, fetcher, config)
                    # Inject check_id into each issue
                    for issue in issues:
                        if issue.check_id is None:
                            issue.check_id = check.check_id
                    # Filter issues based on ignore_patterns
                    filtered_issues = [
                        issue for issue in issues if not config.should_ignore(issue, filepath)
                    ]
                    all_issues.extend(filtered_issues)
            return all_issues

        # Execute all checks in parallel
        tasks = []
        configs = []
        for check in enabled_checks:
            config = self.get_config(check.check_id)
            if config:
                task = check.execute(statement, statement_idx, fetcher, config)
                tasks.append(task)
                configs.append(config)

        # Wait for all checks to complete
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Collect all issues, handling any exceptions and applying ignore_patterns
        all_issues = []
        for idx, result in enumerate(results):
            if isinstance(result, Exception):
                # Log error but continue with other checks
                check = enabled_checks[idx]
                print(f"Warning: Check '{check.check_id}' failed: {result}")
            elif isinstance(result, list):
                check = enabled_checks[idx]
                config = configs[idx]
                # Inject check_id into each issue
                for issue in result:
                    if issue.check_id is None:
                        issue.check_id = check.check_id
                # Filter issues based on ignore_patterns
                filtered_issues = [
                    issue for issue in result if not config.should_ignore(issue, filepath)
                ]
                all_issues.extend(filtered_issues)

        return all_issues

    async def execute_checks_sequential(
        self,
        statement: Statement,
        statement_idx: int,
        fetcher: AWSServiceFetcher,
    ) -> list[ValidationIssue]:
        """
        Execute all enabled checks sequentially.

        Useful for debugging or when parallel execution causes issues.

        Args:
            statement: The IAM policy statement to validate
            statement_idx: Index of the statement in the policy
            fetcher: AWS service fetcher for API calls

        Returns:
            List of all ValidationIssue objects from all checks
        """
        all_issues = []
        enabled_checks = self.get_enabled_checks()

        for check in enabled_checks:
            config = self.get_config(check.check_id)
            if config:
                try:
                    issues = await check.execute(statement, statement_idx, fetcher, config)
                    all_issues.extend(issues)
                except Exception as e:
                    print(f"Warning: Check '{check.check_id}' failed: {e}")

        return all_issues

    async def execute_policy_checks(
        self,
        policy: "IAMPolicy",
        policy_file: str,
        fetcher: AWSServiceFetcher,
        policy_type: str = "IDENTITY_POLICY",
        **kwargs,
    ) -> list[ValidationIssue]:
        """
        Execute all enabled policy-level checks.

        Policy-level checks examine the entire policy at once, which is useful for
        checks that need to see relationships between statements (e.g., duplicate SIDs).

        Args:
            policy: The complete IAM policy to validate
            policy_file: Path to the policy file (for context/reporting)
            fetcher: AWS service fetcher for API calls
            policy_type: Type of policy (IDENTITY_POLICY, RESOURCE_POLICY, SERVICE_CONTROL_POLICY)
            **kwargs: Additional arguments to pass to checks (e.g., raw_policy_dict)

        Returns:
            List of all ValidationIssue objects from all policy-level checks
        """
        all_issues = []
        enabled_checks = self.get_enabled_checks()

        # Filter to only policy-level checks
        policy_level_checks = [c for c in enabled_checks if c.is_policy_level_check()]

        if not policy_level_checks:
            return []

        if not self.enable_parallel or len(policy_level_checks) == 1:
            # Run sequentially if parallel disabled or only one check
            for check in policy_level_checks:
                config = self.get_config(check.check_id)
                if config:
                    try:
                        issues = await check.execute_policy(
                            policy,
                            policy_file,
                            fetcher,
                            config,
                            policy_type=policy_type,
                            **kwargs,
                        )
                        # Inject check_id into each issue
                        for issue in issues:
                            if issue.check_id is None:
                                issue.check_id = check.check_id
                        # Filter issues based on ignore_patterns
                        filtered_issues = [
                            issue
                            for issue in issues
                            if not config.should_ignore(issue, policy_file)
                        ]
                        all_issues.extend(filtered_issues)
                    except Exception as e:
                        print(f"Warning: Check '{check.check_id}' failed: {e}")
            return all_issues

        # Execute all policy-level checks in parallel
        tasks = []
        configs = []
        for check in policy_level_checks:
            config = self.get_config(check.check_id)
            if config:
                task = check.execute_policy(
                    policy, policy_file, fetcher, config, policy_type=policy_type, **kwargs
                )
                tasks.append(task)
                configs.append(config)

        # Wait for all checks to complete
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Collect all issues, handling any exceptions and applying ignore_patterns
        for idx, result in enumerate(results):
            if isinstance(result, Exception):
                # Log error but continue with other checks
                check = policy_level_checks[idx]
                print(f"Warning: Check '{check.check_id}' failed: {result}")
            elif isinstance(result, list):
                check = policy_level_checks[idx]
                config = configs[idx]
                # Inject check_id into each issue
                for issue in result:
                    if issue.check_id is None:
                        issue.check_id = check.check_id
                # Filter issues based on ignore_patterns
                filtered_issues = [
                    issue for issue in result if not config.should_ignore(issue, policy_file)
                ]
                all_issues.extend(filtered_issues)

        return all_issues


def create_default_registry(
    enable_parallel: bool = True, include_builtin_checks: bool = True
) -> CheckRegistry:
    """
    Create a registry with all built-in checks registered.

    This is a factory function that will be called when no custom
    registry is provided.

    Args:
        enable_parallel: If True, checks will execute in parallel (default: True)
        include_builtin_checks: If True, register built-in checks (default: True)

    Returns:
        CheckRegistry with all built-in checks registered (if include_builtin_checks=True)
    """
    registry = CheckRegistry(enable_parallel=enable_parallel)

    if include_builtin_checks:
        # Import and register built-in checks
        from iam_validator import checks

        # 0. FUNDAMENTAL STRUCTURE (Must run FIRST - validates basic policy structure)
        registry.register(
            checks.PolicyStructureCheck()
        )  # Policy-level: Validates required fields, conflicts, valid values

        # 1. POLICY STRUCTURE (Checks that examine the entire policy, not individual statements)
        registry.register(
            checks.SidUniquenessCheck()
        )  # Policy-level: Duplicate SID detection across statements
        registry.register(checks.PolicySizeCheck())  # Policy-level: Size limit validation

        # 2. IAM VALIDITY (AWS syntax validation - must pass before deeper checks)
        registry.register(checks.ActionValidationCheck())  # Validate actions against AWS API
        registry.register(checks.ResourceValidationCheck())  # Validate resource ARNs
        registry.register(checks.ConditionKeyValidationCheck())  # Validate condition keys

        # 3. TYPE VALIDATION (Condition operator type checking)
        registry.register(checks.ConditionTypeMismatchCheck())  # Operator-value type compatibility
        registry.register(checks.SetOperatorValidationCheck())  # ForAllValues/ForAnyValue usage

        # 4. RESOURCE MATCHING (Action-resource relationship validation)
        registry.register(
            checks.ActionResourceMatchingCheck()
        )  # ARN type matching and resource constraints

        # 5. SECURITY - WILDCARDS (Security best practices for wildcards)
        registry.register(checks.WildcardActionCheck())  # Wildcard action detection
        registry.register(checks.WildcardResourceCheck())  # Wildcard resource detection
        registry.register(checks.FullWildcardCheck())  # Full wildcard (*) detection
        registry.register(checks.ServiceWildcardCheck())  # Service-level wildcard detection

        # 6. SECURITY - ADVANCED (Sensitive actions and condition enforcement)
        registry.register(
            checks.SensitiveActionCheck()
        )  # Policy-level: Privilege escalation detection (all_of across statements)
        registry.register(
            checks.ActionConditionEnforcementCheck()
        )  # Statement + Policy-level: Condition enforcement (any_of/all_of/none_of)
        registry.register(checks.MFAConditionCheck())  # MFA anti-pattern detection

        # 7. PRINCIPAL VALIDATION (Resource policy specific)
        registry.register(
            checks.PrincipalValidationCheck()
        )  # Principal validation (resource policies)
        registry.register(
            checks.TrustPolicyValidationCheck()
        )  # Trust policy validation (role assumption policies)

        # Note: policy_type_validation is a standalone function (not a class-based check)
        # and is called separately in the validation flow

    return registry
