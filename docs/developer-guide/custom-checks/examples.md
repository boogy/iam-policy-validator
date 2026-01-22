---
title: Custom Check Examples
description: Real-world custom check examples
---

# Custom Check Examples

Real-world examples of custom validation checks.

## Encryption Required

Require encryption for S3 write operations:

```python
from typing import ClassVar

from iam_validator.core.check_registry import PolicyCheck, CheckConfig
from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.models import Statement, ValidationIssue


class EncryptionRequiredCheck(PolicyCheck):
    """Ensures S3 write operations require encryption."""

    check_id: ClassVar[str] = "s3_encryption_required"
    description: ClassVar[str] = "Ensures S3 writes require encryption"
    default_severity: ClassVar[str] = "high"

    S3_WRITE_ACTIONS = {"s3:PutObject", "s3:PutObjectAcl", "s3:ReplicateObject"}

    async def execute(
        self,
        statement: Statement,
        statement_idx: int,
        fetcher: AWSServiceFetcher,
        config: CheckConfig,
    ) -> list[ValidationIssue]:
        issues = []

        if statement.effect != "Allow":
            return issues

        actions = statement.get_actions()

        for action in actions:
            if action in self.S3_WRITE_ACTIONS:
                if not self._has_encryption_condition(statement):
                    issues.append(
                        ValidationIssue(
                            severity=self.get_severity(config),
                            statement_sid=statement.sid,
                            statement_index=statement_idx,
                            issue_type="missing_encryption",
                            message=f"S3 write '{action}' requires encryption",
                            action=action,
                            suggestion="Add s3:x-amz-server-side-encryption condition",
                            line_number=statement.line_number,
                        )
                    )

        return issues

    def _has_encryption_condition(self, statement: Statement) -> bool:
        if not statement.condition:
            return False

        for operator, conditions in statement.condition.items():
            if "s3:x-amz-server-side-encryption" in conditions:
                return True

        return False
```

## Production Wildcard Block

Block wildcards in production resources:

```python
from typing import ClassVar

from iam_validator.core.check_registry import PolicyCheck, CheckConfig
from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.models import Statement, ValidationIssue


class ProductionWildcardCheck(PolicyCheck):
    """Blocks wildcards in production resources."""

    check_id: ClassVar[str] = "production_wildcard"
    description: ClassVar[str] = "Blocks wildcards in production"
    default_severity: ClassVar[str] = "critical"

    async def execute(
        self,
        statement: Statement,
        statement_idx: int,
        fetcher: AWSServiceFetcher,
        config: CheckConfig,
    ) -> list[ValidationIssue]:
        issues = []

        resources = statement.get_resources()

        for resource in resources:
            if "production" in resource.lower() and "*" in resource:
                issues.append(
                    ValidationIssue(
                        severity=self.get_severity(config),
                        statement_sid=statement.sid,
                        statement_index=statement_idx,
                        issue_type="production_wildcard",
                        message=f"Production resource has wildcard: {resource}",
                        resource=resource,
                        suggestion="Use specific resource identifiers",
                        line_number=statement.line_number,
                    )
                )

        return issues
```

## Region Restriction

Enforce approved AWS regions:

```python
from typing import ClassVar

from iam_validator.core.check_registry import PolicyCheck, CheckConfig
from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.models import Statement, ValidationIssue


class RegionRestrictionCheck(PolicyCheck):
    """Enforces approved AWS regions."""

    check_id: ClassVar[str] = "region_restriction"
    description: ClassVar[str] = "Enforces approved regions"
    default_severity: ClassVar[str] = "medium"

    async def execute(
        self,
        statement: Statement,
        statement_idx: int,
        fetcher: AWSServiceFetcher,
        config: CheckConfig,
    ) -> list[ValidationIssue]:
        issues = []

        approved_regions = set(config.config.get("approved_regions", []))
        if not approved_regions:
            return issues

        # Check if region condition exists
        if not self._has_region_condition(statement, approved_regions):
            issues.append(
                ValidationIssue(
                    severity=self.get_severity(config),
                    statement_sid=statement.sid,
                    statement_index=statement_idx,
                    issue_type="missing_region_restriction",
                    message="Statement missing region restriction",
                    suggestion=f"Add aws:RequestedRegion condition: {approved_regions}",
                    line_number=statement.line_number,
                )
            )

        return issues

    def _has_region_condition(self, statement: Statement, approved: set) -> bool:
        if not statement.condition:
            return False

        for operator, conditions in statement.condition.items():
            if "aws:RequestedRegion" in conditions:
                return True

        return False
```

**Configuration:**

```yaml
checks:
  region_restriction:
    enabled: true
    approved_regions:
      - us-east-1
      - us-west-2
      - eu-west-1
```

## More Examples

See the [examples/custom_checks/](https://github.com/boogy/iam-policy-validator/tree/main/examples/custom_checks) directory for additional examples:

| Check                                | Description                   |
| ------------------------------------ | ----------------------------- |
| `domain_restriction_check.py`        | Restrict S3 access to domains |
| `tag_enforcement_check.py`           | Enforce resource tagging      |
| `time_based_access_check.py`         | Business hours restrictions   |
| `cross_account_external_id_check.py` | Confused deputy prevention    |
