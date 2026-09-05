"""A check that raises must surface as a visible finding, never as silence."""

from typing import ClassVar

import pytest

from iam_validator.core.check_registry import CheckRegistry, PolicyCheck
from iam_validator.core.models import Statement, ValidationIssue


class ExplodingCheck(PolicyCheck):
    check_id: ClassVar[str] = "exploding_check"
    description: ClassVar[str] = "Always raises"
    default_severity: ClassVar[str] = "medium"

    async def execute(self, statement, statement_idx, fetcher, config) -> list[ValidationIssue]:
        raise RuntimeError("boom")


class QuietCheck(PolicyCheck):
    check_id: ClassVar[str] = "quiet_check"
    description: ClassVar[str] = "Never finds anything"
    default_severity: ClassVar[str] = "medium"

    async def execute(self, statement, statement_idx, fetcher, config) -> list[ValidationIssue]:
        return []


@pytest.fixture
def statement() -> Statement:
    return Statement(effect="Allow", action=["s3:GetObject"], resource=["*"], sid="Sid1")


@pytest.mark.parametrize("enable_parallel", [True, False])
async def test_crashed_check_reports_error_finding(statement, enable_parallel):
    registry = CheckRegistry(enable_parallel=enable_parallel)
    registry.register(ExplodingCheck())
    registry.register(QuietCheck())

    issues = await registry.execute_checks_parallel(statement, 0, fetcher=None)

    assert [i.issue_type for i in issues] == ["check_execution_error"]
    assert issues[0].severity == "error"
    assert issues[0].check_id == "exploding_check"
    assert issues[0].statement_index == 0
    assert issues[0].statement_sid == "Sid1"
    assert "RuntimeError" in issues[0].message
    assert "boom" in issues[0].message


async def test_crashed_check_does_not_abort_sequential_run(statement):
    registry = CheckRegistry(enable_parallel=False)
    registry.register(ExplodingCheck())
    registry.register(QuietCheck())

    issues = await registry.execute_checks_sequential(statement, 0, fetcher=None)

    assert [i.issue_type for i in issues] == ["check_execution_error"]


async def test_healthy_checks_emit_no_execution_error(statement):
    registry = CheckRegistry()
    registry.register(QuietCheck())

    issues = await registry.execute_checks_parallel(statement, 0, fetcher=None)

    assert issues == []
