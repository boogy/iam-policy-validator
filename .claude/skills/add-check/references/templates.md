# Check Templates

## Table of Contents

1. [Statement-Level Check Template](#statement-level-check-template)
2. [Policy-Level Check Template](#policy-level-check-template)
3. [Combined Check Template](#combined-check-template)
4. [Statement-Level Test Template](#statement-level-test-template)
5. [Policy-Level Test Template](#policy-level-test-template)

## Statement-Level Check Template

```python
"""Check description - validates X at the statement level."""

from typing import ClassVar

from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig, PolicyCheck
from iam_validator.core.models import Statement, ValidationIssue


class {CheckName}Check(PolicyCheck):
    """Detailed description of what this check validates."""

    check_id: ClassVar[str] = "{check_name}"
    description: ClassVar[str] = "Brief description for --help"
    default_severity: ClassVar[str] = "{severity}"

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
        resources = statement.get_resources()

        for action in actions:
            if self._is_problematic(action):
                issues.append(
                    ValidationIssue(
                        severity=self.get_severity(config),
                        statement_sid=statement.sid,
                        statement_index=statement_idx,
                        issue_type="{check_name}",
                        message=f"Found problematic action: {action}",
                        action=action,
                        suggestion="Replace with a more specific action",
                        line_number=statement.line_number,
                        field_name="action",
                    )
                )

        return issues

    def _is_problematic(self, action: str) -> bool:
        return action == "*"
```

## Policy-Level Check Template

```python
"""Check description - validates X across the entire policy."""

from typing import ClassVar

from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig, PolicyCheck
from iam_validator.core.models import IAMPolicy, ValidationIssue


class {CheckName}Check(PolicyCheck):
    """Detailed description. Policy-level check for cross-statement validation."""

    check_id: ClassVar[str] = "{check_name}"
    description: ClassVar[str] = "Brief description for --help"
    default_severity: ClassVar[str] = "{severity}"

    async def execute_policy(
        self,
        policy: IAMPolicy,
        policy_file: str,
        fetcher: AWSServiceFetcher,
        config: CheckConfig,
        **kwargs,
    ) -> list[ValidationIssue]:
        del policy_file, fetcher
        issues = []
        severity = self.get_severity(config)

        if not policy.statement:
            return issues

        seen_actions: dict[frozenset[str], int] = {}

        for idx, statement in enumerate(policy.statement):
            if statement.effect != "Allow":
                continue

            action_set = frozenset(statement.get_actions())

            if action_set in seen_actions:
                original_idx = seen_actions[action_set]
                issues.append(
                    ValidationIssue(
                        severity=severity,
                        statement_sid=statement.sid,
                        statement_index=idx,
                        issue_type="{check_name}",
                        message=f"Statement #{idx + 1} has identical actions to statement #{original_idx + 1}",
                        suggestion="Consider consolidating these statements",
                        line_number=statement.line_number,
                    )
                )
            else:
                seen_actions[action_set] = idx

        return issues
```

## Combined Check Template

```python
"""Check description - validates X at both statement and policy level."""

from typing import ClassVar

from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.check_registry import CheckConfig, PolicyCheck
from iam_validator.core.models import IAMPolicy, Statement, ValidationIssue


class {CheckName}Check(PolicyCheck):
    """Both statement-level and policy-level validation."""

    check_id: ClassVar[str] = "{check_name}"
    description: ClassVar[str] = "Brief description for --help"
    default_severity: ClassVar[str] = "{severity}"

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
            if self._is_problematic_action(action):
                issues.append(
                    ValidationIssue(
                        severity=self.get_severity(config),
                        statement_sid=statement.sid,
                        statement_index=statement_idx,
                        issue_type="{check_name}_statement",
                        message=f"Found problematic action: {action}",
                        action=action,
                        suggestion="Use a more restrictive action",
                        line_number=statement.line_number,
                        field_name="action",
                    )
                )
        return issues

    async def execute_policy(
        self,
        policy: IAMPolicy,
        policy_file: str,
        fetcher: AWSServiceFetcher,
        config: CheckConfig,
        **kwargs,
    ) -> list[ValidationIssue]:
        del policy_file, fetcher
        issues = []
        severity = self.get_severity(config)

        if not policy.statement:
            return issues

        total_problematic = 0
        for statement in policy.statement:
            if statement.effect == "Allow":
                for action in statement.get_actions():
                    if self._is_problematic_action(action):
                        total_problematic += 1

        if total_problematic > 5:
            issues.append(
                ValidationIssue(
                    severity=severity,
                    statement_sid=None,
                    statement_index=-1,
                    issue_type="{check_name}_policy",
                    message=f"Policy contains {total_problematic} problematic actions",
                    suggestion="Review and reduce problematic actions",
                    line_number=None,
                )
            )
        return issues

    def _is_problematic_action(self, action: str) -> bool:
        return action == "*" or action.endswith(":*")
```

## Statement-Level Test Template

```python
import pytest
from iam_validator.checks.{check_name} import {CheckName}Check
from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.models import Statement


class Test{CheckName}Check:
    @pytest.fixture
    def check(self):
        return {CheckName}Check()

    @pytest.fixture
    def config(self):
        return CheckConfig(check_id="{check_name}", enabled=True)

    @pytest.fixture
    def mock_fetcher(self, mocker):
        fetcher = mocker.MagicMock()
        fetcher.validate_action = mocker.AsyncMock(return_value=(True, None, False))
        return fetcher

    @pytest.mark.asyncio
    async def test_detects_issue(self, check, config, mock_fetcher):
        statement = Statement(effect="Allow", action=["*"], resource=["*"])
        issues = await check.execute(statement, 0, mock_fetcher, config)
        assert len(issues) == 1
        assert issues[0].issue_type == "{check_name}"

    @pytest.mark.asyncio
    async def test_allows_valid_statement(self, check, config, mock_fetcher):
        statement = Statement(
            effect="Allow",
            action=["s3:GetObject"],
            resource=["arn:aws:s3:::my-bucket/*"],
        )
        issues = await check.execute(statement, 0, mock_fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_ignores_deny_statements(self, check, config, mock_fetcher):
        statement = Statement(effect="Deny", action=["*"], resource=["*"])
        issues = await check.execute(statement, 0, mock_fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_respects_severity_override(self, check, mock_fetcher):
        config = CheckConfig(check_id="{check_name}", enabled=True, severity="critical")
        statement = Statement(effect="Allow", action=["*"], resource=["*"])
        issues = await check.execute(statement, 0, mock_fetcher, config)
        assert len(issues) == 1
        assert issues[0].severity == "critical"
```

## Policy-Level Test Template

```python
import pytest
from iam_validator.checks.{check_name} import {CheckName}Check
from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.models import IAMPolicy, Statement


class Test{CheckName}Check:
    @pytest.fixture
    def check(self):
        return {CheckName}Check()

    @pytest.fixture
    def config(self):
        return CheckConfig(check_id="{check_name}", enabled=True)

    @pytest.fixture
    def mock_fetcher(self, mocker):
        return mocker.MagicMock()

    @pytest.mark.asyncio
    async def test_detects_policy_issue(self, check, config, mock_fetcher):
        policy = IAMPolicy(
            version="2012-10-17",
            statement=[
                Statement(effect="Allow", action=["s3:GetObject"], resource=["*"], sid="First"),
                Statement(effect="Allow", action=["s3:GetObject"], resource=["*"], sid="Duplicate"),
            ],
        )
        issues = await check.execute_policy(policy, "test.json", mock_fetcher, config)
        assert len(issues) == 1
        assert issues[0].issue_type == "{check_name}"

    @pytest.mark.asyncio
    async def test_allows_valid_policy(self, check, config, mock_fetcher):
        policy = IAMPolicy(
            version="2012-10-17",
            statement=[
                Statement(effect="Allow", action=["s3:GetObject"], resource=["*"], sid="Read"),
                Statement(effect="Allow", action=["s3:PutObject"], resource=["*"], sid="Write"),
            ],
        )
        issues = await check.execute_policy(policy, "test.json", mock_fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_handles_empty_policy(self, check, config, mock_fetcher):
        policy = IAMPolicy(version="2012-10-17", statement=[])
        issues = await check.execute_policy(policy, "test.json", mock_fetcher, config)
        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_respects_severity_override(self, check, mock_fetcher):
        config = CheckConfig(check_id="{check_name}", enabled=True, severity="critical")
        policy = IAMPolicy(
            version="2012-10-17",
            statement=[
                Statement(effect="Allow", action=["s3:GetObject"], resource=["*"]),
                Statement(effect="Allow", action=["s3:GetObject"], resource=["*"]),
            ],
        )
        issues = await check.execute_policy(policy, "test.json", mock_fetcher, config)
        if issues:
            assert issues[0].severity == "critical"
```
