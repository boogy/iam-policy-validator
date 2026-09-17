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
    default_severity: ClassVar[str]   # Default severity level ("warning" when omitted)

    # Check ids this check's findings supersede, when matches() is also True
    supersedes: ClassVar[frozenset[str]] = frozenset()

    # PolicyType values this check is meaningful for; None (default) means all
    applies_to_policy_types: ClassVar[frozenset[str] | None] = None

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

    def matches(self, statement: Statement) -> bool:
        """True if this check dominates the statement. Only read when supersedes is set."""
        ...

    def applies_to(self, policy_type: str | None) -> bool:
        """True when the check is meaningful for policy_type; None means all types."""
        ...
```

`applies_to_policy_types` is how a check opts out of a policy type it cannot reason
about. In an SCP or RCP an `Allow` declines to restrict rather than granting access, so
the grant-shaped checks (`full_wildcard`, `service_wildcard`, `wildcard_action`,
`wildcard_resource`, `sensitive_action`, `action_condition_enforcement`) exclude
`SERVICE_CONTROL_POLICY` and `RESOURCE_CONTROL_POLICY`; `principal_validation` excludes
only RCP, where AWS syntax requires `Principal: "*"`. Registration raises `ValueError`
on a value that is not a `PolicyType`.

## CheckConfig

Configuration passed to checks.

```python
class CheckConfig:
    check_id: str                   # Check identifier
    enabled: bool                   # Whether check is enabled
    severity: str | None            # Severity override
    config: dict                    # Check-specific config
    description: str                # Description override
    root_config: dict               # Full config, for cross-check access
    ignore_patterns: list[dict]     # Patterns whose findings are dropped
    hide_severities: frozenset[str] | None   # Severities removed from the run
```

`root_config` is the whole resolved configuration, so a check can ask another check what
it is configured to do — see [`enforced_actions`](#enforced_actions) below.

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

## enforced_actions

`ActionConditionEnforcementCheck.enforced_actions(root_config, policy_file=None)` is the
supported way for another check to find out which actions `action_condition_enforcement`
will actually report on, so it can suppress its own duplicate finding.

```python
from iam_validator.checks.action_condition_enforcement import ActionConditionEnforcementCheck
from iam_validator.checks.utils.aws_matching import action_matches

covered = ActionConditionEnforcementCheck.enforced_actions(config.root_config)
if any(action_matches(action, pattern) for pattern in covered):
    return []  # action_condition_enforcement reports this one
```

It returns the action patterns as configured — match them with `action_matches`, not
`==`, because a pattern may be a glob (`iam:Pass*` covers `iam:PassRole`) and IAM action
names are case-insensitive. It returns an empty set when the check is disabled, and it
honours `merge_strategy`, user-supplied `action_condition_requirements` and
`ignore_patterns`, so a requirement that is configured out of play is not returned.

Pass `policy_file` when you have it: without it a requirement scoped by an
`ignore_patterns` `filepath` cannot be evaluated and counts as _not_ enforced, which errs
toward a possible duplicate rather than dropping a real finding. Statement-level checks
receive no `policy_file`; policy-level checks get it as the second argument to
`execute_policy`.

See
[Custom Checks Best Practices](../developer-guide/custom-checks/best-practices.md#deduplicating-against-another-check)
for the full call-site guidance.

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
