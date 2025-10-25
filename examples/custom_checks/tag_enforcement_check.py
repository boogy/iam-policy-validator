"""
Example custom check: Tag Enforcement Check

This check ensures that resource creation/modification actions require specific tags.
Useful for cost allocation, compliance tracking, and resource organization.

Usage:
    Add to your iam-validator.yaml:

        custom_checks_dir: "./examples/custom_checks"

        checks:
          tag_enforcement:
            enabled: true
            severity: warning
            # Actions that must include tagging conditions
            require_tags_for:
              - "ec2:RunInstances"
              - "s3:CreateBucket"
              - "dynamodb:CreateTable"
            # Required tag keys
            required_tags:
              - "Environment"
              - "Owner"
              - "CostCenter"
"""

from iam_validator.core.aws_fetcher import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig, PolicyCheck
from iam_validator.core.models import Statement, ValidationIssue


class TagEnforcementCheck(PolicyCheck):
    """Ensures resource operations include required tag conditions."""

    @property
    def check_id(self) -> str:
        return "tag_enforcement"

    @property
    def description(self) -> str:
        return "Ensures resource operations require appropriate tags"

    @property
    def default_severity(self) -> str:
        return "warning"

    async def execute(
        self,
        statement: Statement,
        statement_idx: int,
        fetcher: AWSServiceFetcher,
        config: CheckConfig,
    ) -> list[ValidationIssue]:
        """Check tag enforcement requirements."""
        issues = []

        # Only check Allow statements
        if statement.effect != "Allow":
            return issues

        require_tags_for = set(config.config.get("require_tags_for", []))
        required_tags = config.config.get("required_tags", [])

        if not require_tags_for or not required_tags:
            return issues

        actions = statement.get_actions()

        for action in actions:
            if action == "*":
                continue

            if action in require_tags_for:
                missing_tags = self._check_tag_conditions(statement, required_tags)

                if missing_tags:
                    issues.append(
                        ValidationIssue(
                            severity=self.get_severity(config),
                            statement_sid=statement.sid,
                            statement_index=statement_idx,
                            issue_type="missing_tag_condition",
                            message=f"Action '{action}' should enforce required tags: {', '.join(missing_tags)}",
                            action=action,
                            suggestion=f"Add conditions for aws:RequestTag/* to enforce tags: {', '.join(missing_tags)}",
                            line_number=statement.line_number,
                        )
                    )

        return issues

    def _check_tag_conditions(self, statement: Statement, required_tags: list[str]) -> list[str]:
        """
        Check which required tags are missing from conditions.

        Returns:
            List of missing tag names
        """
        if not statement.condition:
            return required_tags

        # Look for tag conditions
        found_tags = set()

        for operator, conditions in statement.condition.items():
            for condition_key in conditions.keys():
                # Check for aws:RequestTag/TagName patterns
                if condition_key.startswith("aws:RequestTag/"):
                    tag_name = condition_key.replace("aws:RequestTag/", "")
                    found_tags.add(tag_name)

                # Also check for StringLike on aws:RequestTag keys
                if condition_key == "aws:TagKeys":
                    # TagKeys condition lists tag keys that must be present
                    tag_value = conditions[condition_key]
                    if isinstance(tag_value, list):
                        found_tags.update(tag_value)
                    elif isinstance(tag_value, str):
                        found_tags.add(tag_value)

        # Return missing tags
        missing_tags = [tag for tag in required_tags if tag not in found_tags]
        return missing_tags
