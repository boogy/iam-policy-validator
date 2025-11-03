"""Principal Validation Check.

Validates Principal elements in resource-based policies for security best practices.
This check enforces:
- Blocked principals (e.g., public access via "*")
- Allowed principals whitelist (optional)
- Required conditions for specific principals
- Service principal validation

Only runs for RESOURCE_POLICY type policies.
"""

import fnmatch

from iam_validator.core.aws_fetcher import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig, PolicyCheck
from iam_validator.core.models import Statement, ValidationIssue


class PrincipalValidationCheck(PolicyCheck):
    """Validates Principal elements in resource policies."""

    @property
    def check_id(self) -> str:
        return "principal_validation_check"

    @property
    def description(self) -> str:
        return "Validates Principal elements in resource policies for security best practices"

    @property
    def default_severity(self) -> str:
        return "high"

    async def execute(
        self,
        statement: Statement,
        statement_idx: int,
        fetcher: AWSServiceFetcher,
        config: CheckConfig,
    ) -> list[ValidationIssue]:
        """Execute principal validation on a single statement.

        Args:
            statement: The statement to validate
            statement_idx: Index of the statement in the policy
            fetcher: AWS service fetcher instance
            config: Configuration for this check

        Returns:
            List of validation issues
        """
        issues = []

        # Skip if no principal
        if statement.principal is None and statement.not_principal is None:
            return issues

        # Get configuration
        blocked_principals = config.config.get("blocked_principals", ["*"])
        allowed_principals = config.config.get("allowed_principals", [])
        require_conditions_for = config.config.get("require_conditions_for", {})
        allowed_service_principals = config.config.get(
            "allowed_service_principals",
            [
                "cloudfront.amazonaws.com",
                "s3.amazonaws.com",
                "sns.amazonaws.com",
                "lambda.amazonaws.com",
                "logs.amazonaws.com",
                "events.amazonaws.com",
            ],
        )

        # Extract principals from statement
        principals = self._extract_principals(statement)

        for principal in principals:
            # Check if principal is blocked
            if self._is_blocked_principal(
                principal, blocked_principals, allowed_service_principals
            ):
                issues.append(
                    ValidationIssue(
                        severity=self.get_severity(config),
                        issue_type="blocked_principal",
                        message=f"Blocked principal detected: {principal}. "
                        f"This principal is explicitly blocked by your security policy.",
                        statement_index=statement_idx,
                        statement_sid=statement.sid,
                        line_number=statement.line_number,
                        suggestion=f"Remove the principal '{principal}' or add appropriate conditions to restrict access. "
                        "Consider using more specific principals instead of wildcards.",
                    )
                )
                continue

            # Check if principal is in whitelist (if whitelist is configured)
            if allowed_principals and not self._is_allowed_principal(
                principal, allowed_principals, allowed_service_principals
            ):
                issues.append(
                    ValidationIssue(
                        severity=self.get_severity(config),
                        issue_type="unauthorized_principal",
                        message=f"Principal not in allowed list: {principal}. "
                        f"Only principals in the allowed_principals whitelist are permitted.",
                        statement_index=statement_idx,
                        statement_sid=statement.sid,
                        line_number=statement.line_number,
                        suggestion=f"Add '{principal}' to the allowed_principals list in your config, "
                        "or use a principal that matches an allowed pattern.",
                    )
                )
                continue

            # Check if principal requires conditions
            required_conditions = self._get_required_conditions(principal, require_conditions_for)
            if required_conditions:
                missing_conditions = self._check_required_conditions(statement, required_conditions)
                if missing_conditions:
                    issues.append(
                        ValidationIssue(
                            severity=self.get_severity(config),
                            issue_type="missing_principal_conditions",
                            message=f"Principal '{principal}' requires conditions: {', '.join(missing_conditions)}. "
                            f"This principal must have these condition keys to restrict access.",
                            statement_index=statement_idx,
                            statement_sid=statement.sid,
                            line_number=statement.line_number,
                            suggestion=f"Add conditions to restrict access:\n"
                            f"Example:\n"
                            f'"Condition": {{\n'
                            f'  "StringEquals": {{\n'
                            f'    "{missing_conditions[0]}": "value"\n'
                            f"  }}\n"
                            f"}}",
                        )
                    )

        return issues

    def _extract_principals(self, statement: Statement) -> list[str]:
        """Extract all principals from a statement.

        Args:
            statement: The statement to extract principals from

        Returns:
            List of principal strings
        """
        principals = []

        # Handle Principal field
        if statement.principal:
            if isinstance(statement.principal, str):
                # Simple string principal like "*"
                principals.append(statement.principal)
            elif isinstance(statement.principal, dict):
                # Dict with AWS, Service, Federated, etc.
                for key, value in statement.principal.items():
                    if isinstance(value, str):
                        principals.append(value)
                    elif isinstance(value, list):
                        principals.extend(value)

        # Handle NotPrincipal field (similar logic)
        if statement.not_principal:
            if isinstance(statement.not_principal, str):
                principals.append(statement.not_principal)
            elif isinstance(statement.not_principal, dict):
                for key, value in statement.not_principal.items():
                    if isinstance(value, str):
                        principals.append(value)
                    elif isinstance(value, list):
                        principals.extend(value)

        return principals

    def _is_blocked_principal(
        self, principal: str, blocked_list: list[str], service_whitelist: list[str]
    ) -> bool:
        """Check if a principal is blocked.

        Args:
            principal: The principal to check
            blocked_list: List of blocked principal patterns
            service_whitelist: List of allowed service principals

        Returns:
            True if the principal is blocked
        """
        # Service principals are never blocked
        if principal in service_whitelist:
            return False

        # Check against blocked list (supports wildcards)
        for blocked_pattern in blocked_list:
            # Special case: "*" in blocked list should only match literal "*" (public access)
            # not use it as a wildcard pattern that matches everything
            if blocked_pattern == "*":
                if principal == "*":
                    return True
            elif fnmatch.fnmatch(principal, blocked_pattern):
                return True

        return False

    def _is_allowed_principal(
        self, principal: str, allowed_list: list[str], service_whitelist: list[str]
    ) -> bool:
        """Check if a principal is in the allowed list.

        Args:
            principal: The principal to check
            allowed_list: List of allowed principal patterns
            service_whitelist: List of allowed service principals

        Returns:
            True if the principal is allowed
        """
        # Service principals are always allowed
        if principal in service_whitelist:
            return True

        # Check against allowed list (supports wildcards)
        for allowed_pattern in allowed_list:
            # Special case: "*" in allowed list should only match literal "*" (public access)
            # not use it as a wildcard pattern that matches everything
            if allowed_pattern == "*":
                if principal == "*":
                    return True
            elif fnmatch.fnmatch(principal, allowed_pattern):
                return True

        return False

    def _get_required_conditions(
        self, principal: str, requirements: dict[str, list[str]]
    ) -> list[str]:
        """Get required condition keys for a principal.

        Args:
            principal: The principal to check
            requirements: Dict mapping principal patterns to required condition keys

        Returns:
            List of required condition keys
        """
        for pattern, condition_keys in requirements.items():
            # Special case: "*" pattern should only match literal "*" (public access)
            if pattern == "*":
                if principal == "*":
                    return condition_keys
            elif fnmatch.fnmatch(principal, pattern):
                return condition_keys
        return []

    def _check_required_conditions(
        self, statement: Statement, required_keys: list[str]
    ) -> list[str]:
        """Check if statement has required condition keys.

        Args:
            statement: The statement to check
            required_keys: List of required condition keys

        Returns:
            List of missing condition keys
        """
        if not statement.condition:
            return required_keys

        # Flatten all condition keys from all condition operators
        present_keys = set()
        for operator_conditions in statement.condition.values():
            if isinstance(operator_conditions, dict):
                present_keys.update(operator_conditions.keys())

        # Find missing keys
        missing = [key for key in required_keys if key not in present_keys]
        return missing
