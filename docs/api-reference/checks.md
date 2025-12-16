---
title: Checks API
description: Check base class reference
---

# Checks API Reference

## PolicyCheck

Base class for all validation checks.

```python
from typing import ClassVar
from iam_validator.core.check_registry import PolicyCheck, CheckConfig
from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.models import Statement, IAMPolicy, ValidationIssue


class PolicyCheck:
    """Base class for validation checks."""

    check_id: ClassVar[str]           # Unique identifier
    description: ClassVar[str]        # What the check does
    default_severity: ClassVar[str]   # Default severity level

    async def execute(
        self,
        statement: Statement,
        statement_idx: int,
        fetcher: AWSServiceFetcher,
        config: CheckConfig,
    ) -> list[ValidationIssue]:
        """Execute check on a single statement."""
        ...

    async def execute_policy(
        self,
        policy: IAMPolicy,
        policy_file: str,
        fetcher: AWSServiceFetcher,
        config: CheckConfig,
        **kwargs,
    ) -> list[ValidationIssue]:
        """Execute check on entire policy (optional)."""
        ...

    def get_severity(self, config: CheckConfig) -> str:
        """Get effective severity (config override or default)."""
        ...
```

## CheckConfig

Configuration passed to checks.

```python
class CheckConfig:
    check_id: str           # Check identifier
    enabled: bool           # Whether check is enabled
    severity: str | None    # Severity override
    config: dict            # Check-specific config
```

## CheckRegistry

Registry for managing checks.

```python
from iam_validator.core.check_registry import CheckRegistry

# Register a check
CheckRegistry.register_check(MyCheck)

# Get all registered checks
checks = CheckRegistry.get_all_checks()

# Execute checks
issues = await registry.execute_checks_parallel(
    statement, idx, fetcher, config
)
```

## Creating a Check

```python
from typing import ClassVar

from iam_validator.core.check_registry import PolicyCheck, CheckConfig
from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.models import Statement, ValidationIssue


class MyCheck(PolicyCheck):
    check_id: ClassVar[str] = "my_check"
    description: ClassVar[str] = "My custom check"
    default_severity: ClassVar[str] = "high"

    async def execute(
        self,
        statement: Statement,
        statement_idx: int,
        fetcher: AWSServiceFetcher,
        config: CheckConfig,
    ) -> list[ValidationIssue]:
        issues = []

        # Your check logic here

        if problem_found:
            issues.append(
                ValidationIssue(
                    severity=self.get_severity(config),
                    statement_index=statement_idx,
                    statement_sid=statement.sid,
                    issue_type="my_issue",
                    message="Problem description",
                    suggestion="How to fix",
                    line_number=statement.line_number,
                )
            )

        return issues
```
