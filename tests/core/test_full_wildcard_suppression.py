"""Integration tests for full-wildcard suppression (suppress_superseded_findings)."""

from typing import ClassVar
from unittest.mock import AsyncMock, MagicMock

import pytest

from iam_validator.checks.full_wildcard import FullWildcardCheck
from iam_validator.core.check_registry import CheckConfig, CheckRegistry, PolicyCheck
from iam_validator.core.models import Statement, ValidationIssue


def _make_mock_fetcher():
    fetcher = MagicMock()
    fetcher.validate_action = AsyncMock(return_value=(True, None, False))
    fetcher.expand_wildcard_action = AsyncMock(return_value=["s3:GetObject"])
    fetcher.fetch_service_by_name = AsyncMock(return_value=None)
    return fetcher


def _make_registry(suppress: bool = False) -> CheckRegistry:
    return CheckRegistry(suppress_superseded=suppress)


def _make_issue_check_class(check_id: str, severity: str = "medium") -> type:
    """Dynamically create a concrete PolicyCheck subclass that always emits one issue."""

    async def _execute(self, statement, statement_idx, fetcher, config):
        return [
            ValidationIssue(
                severity=self.get_severity(config),
                statement_index=statement_idx,
                issue_type=f"test_{check_id}",
                message=f"Issue from {check_id}",
            )
        ]

    # Build the class with execute defined in the class body to satisfy __init_subclass__
    cls = type(
        f"_Mock_{check_id}",
        (PolicyCheck,),
        {
            "check_id": check_id,
            "description": f"Mock {check_id}",
            "default_severity": severity,
            "execute": _execute,
        },
    )
    return cls


def _add_issue_check(registry: CheckRegistry, check_id: str, severity: str = "medium") -> None:
    """Register a mock check that always emits one issue."""
    cls = _make_issue_check_class(check_id, severity)
    registry.register(cls())
    registry.configure_check(check_id, CheckConfig(check_id=check_id, enabled=True))


class TestSuppressSupersededDefault:
    """With suppress_superseded=False (default), all checks run normally."""

    async def test_all_checks_run_on_full_wildcard(self):
        registry = _make_registry(suppress=False)
        registry.register(FullWildcardCheck())
        registry.configure_check("full_wildcard", CheckConfig(check_id="full_wildcard", enabled=True))
        _add_issue_check(registry, "wildcard_action")
        _add_issue_check(registry, "wildcard_resource")

        statement = Statement(Effect="Allow", Action="*", Resource="*")
        fetcher = _make_mock_fetcher()
        issues = await registry.execute_checks_parallel(statement, 0, fetcher)

        check_ids = {i.check_id for i in issues}
        assert "full_wildcard" in check_ids
        assert "wildcard_action" in check_ids
        assert "wildcard_resource" in check_ids


class TestSuppressSupersededEnabled:
    """With suppress_superseded=True, redundant checks are suppressed for */* statements."""

    async def test_superseded_checks_suppressed_for_full_wildcard(self):
        registry = _make_registry(suppress=True)
        registry.register(FullWildcardCheck())
        registry.configure_check("full_wildcard", CheckConfig(check_id="full_wildcard", enabled=True))
        _add_issue_check(registry, "wildcard_action")
        _add_issue_check(registry, "wildcard_resource")
        _add_issue_check(registry, "sensitive_action")

        statement = Statement(Effect="Allow", Action="*", Resource="*")
        fetcher = _make_mock_fetcher()
        issues = await registry.execute_checks_parallel(statement, 0, fetcher)

        check_ids = {i.check_id for i in issues}
        assert "full_wildcard" in check_ids
        assert "wildcard_action" not in check_ids
        assert "wildcard_resource" not in check_ids
        assert "sensitive_action" not in check_ids

    async def test_suppression_note_added_to_full_wildcard_issue(self):
        registry = _make_registry(suppress=True)
        registry.register(FullWildcardCheck())
        registry.configure_check("full_wildcard", CheckConfig(check_id="full_wildcard", enabled=True))
        _add_issue_check(registry, "wildcard_action")

        statement = Statement(Effect="Allow", Action="*", Resource="*")
        fetcher = _make_mock_fetcher()
        issues = await registry.execute_checks_parallel(statement, 0, fetcher)

        fw_issues = [i for i in issues if i.check_id == "full_wildcard"]
        assert len(fw_issues) == 1
        assert "checks suppressed" in fw_issues[0].message

    async def test_sibling_statement_gets_full_checks(self):
        """Non-wildcard sibling statements should still receive all checks."""
        registry = _make_registry(suppress=True)
        registry.register(FullWildcardCheck())
        registry.configure_check("full_wildcard", CheckConfig(check_id="full_wildcard", enabled=True))
        _add_issue_check(registry, "wildcard_action")

        # Sibling: specific action, resource wildcard — NOT a full */* statement
        statement = Statement(Effect="Allow", Action=["s3:GetObject"], Resource="*")
        fetcher = _make_mock_fetcher()
        issues = await registry.execute_checks_parallel(statement, 0, fetcher)

        check_ids = {i.check_id for i in issues}
        assert "wildcard_action" in check_ids

    async def test_condition_present_still_suppresses(self):
        """Allow */* with conditions still triggers suppression — conditions don't change the root cause."""
        registry = _make_registry(suppress=True)
        registry.register(FullWildcardCheck())
        registry.configure_check("full_wildcard", CheckConfig(check_id="full_wildcard", enabled=True))
        _add_issue_check(registry, "wildcard_action")

        statement = Statement(
            Effect="Allow",
            Action="*",
            Resource="*",
            Condition={"StringEquals": {"aws:ResourceTag/owner": "${aws:PrincipalTag/owner}"}},
        )
        fetcher = _make_mock_fetcher()
        issues = await registry.execute_checks_parallel(statement, 0, fetcher)

        check_ids = {i.check_id for i in issues}
        assert "full_wildcard" in check_ids
        assert "wildcard_action" not in check_ids

    async def test_full_wildcard_disabled_no_suppression(self):
        """When full_wildcard is disabled, no suppression occurs."""
        registry = _make_registry(suppress=True)
        registry.register(FullWildcardCheck())
        registry.configure_check("full_wildcard", CheckConfig(check_id="full_wildcard", enabled=False))
        _add_issue_check(registry, "wildcard_action")
        _add_issue_check(registry, "wildcard_resource")

        statement = Statement(Effect="Allow", Action="*", Resource="*")
        fetcher = _make_mock_fetcher()
        issues = await registry.execute_checks_parallel(statement, 0, fetcher)

        check_ids = {i.check_id for i in issues}
        # full_wildcard disabled so no suppression; other checks run
        assert "wildcard_action" in check_ids
        assert "wildcard_resource" in check_ids

    async def test_deny_statement_no_suppression(self):
        """Deny */* does NOT trigger suppression."""
        registry = _make_registry(suppress=True)
        registry.register(FullWildcardCheck())
        registry.configure_check("full_wildcard", CheckConfig(check_id="full_wildcard", enabled=True))
        _add_issue_check(registry, "wildcard_action")

        statement = Statement(Effect="Deny", Action="*", Resource="*")
        fetcher = _make_mock_fetcher()
        issues = await registry.execute_checks_parallel(statement, 0, fetcher)

        check_ids = {i.check_id for i in issues}
        # No full_wildcard issue (Deny), so no suppression; wildcard_action runs
        assert "wildcard_action" in check_ids

    async def test_duplicate_wildcard_list_suppressed(self):
        """Allow ["*","*"] Resource ["*","*"] still triggers suppression."""
        registry = _make_registry(suppress=True)
        registry.register(FullWildcardCheck())
        registry.configure_check("full_wildcard", CheckConfig(check_id="full_wildcard", enabled=True))
        _add_issue_check(registry, "wildcard_action")

        statement = Statement(Effect="Allow", Action=["*", "*"], Resource=["*", "*"])
        fetcher = _make_mock_fetcher()
        issues = await registry.execute_checks_parallel(statement, 0, fetcher)

        check_ids = {i.check_id for i in issues}
        assert "full_wildcard" in check_ids
        assert "wildcard_action" not in check_ids

    async def test_not_action_no_suppression(self):
        """NotAction:* does NOT trigger suppression."""
        registry = _make_registry(suppress=True)
        registry.register(FullWildcardCheck())
        registry.configure_check("full_wildcard", CheckConfig(check_id="full_wildcard", enabled=True))
        _add_issue_check(registry, "wildcard_action")

        statement = Statement(Effect="Allow", NotAction="*", Resource="*")
        fetcher = _make_mock_fetcher()
        issues = await registry.execute_checks_parallel(statement, 0, fetcher)

        check_ids = {i.check_id for i in issues}
        assert "wildcard_action" in check_ids

    async def test_custom_check_not_in_supersedes_is_not_suppressed(self):
        """Custom checks not declared in supersedes are NOT suppressed for */* statements."""
        registry = _make_registry(suppress=True)
        registry.register(FullWildcardCheck())
        registry.configure_check("full_wildcard", CheckConfig(check_id="full_wildcard", enabled=True))
        _add_issue_check(registry, "my_custom_abac_check")
        _add_issue_check(registry, "another_custom_check")

        statement = Statement(Effect="Allow", Action="*", Resource="*")
        fetcher = _make_mock_fetcher()
        issues = await registry.execute_checks_parallel(statement, 0, fetcher)

        check_ids = {i.check_id for i in issues}
        assert "full_wildcard" in check_ids
        assert "my_custom_abac_check" in check_ids
        assert "another_custom_check" in check_ids

    async def test_suppression_note_lists_only_declared_suppressed_ids(self):
        """Suppression note lists declared supersedes IDs, not unrelated custom checks."""
        registry = _make_registry(suppress=True)
        registry.register(FullWildcardCheck())
        registry.configure_check("full_wildcard", CheckConfig(check_id="full_wildcard", enabled=True))
        _add_issue_check(registry, "wildcard_action")
        _add_issue_check(registry, "my_custom_check")

        statement = Statement(Effect="Allow", Action="*", Resource="*")
        fetcher = _make_mock_fetcher()
        issues = await registry.execute_checks_parallel(statement, 0, fetcher)

        check_ids = {i.check_id for i in issues}
        assert "my_custom_check" in check_ids

        fw_issues = [i for i in issues if i.check_id == "full_wildcard"]
        assert len(fw_issues) == 1
        note = fw_issues[0].message
        assert "wildcard_action" in note
        assert "my_custom_check" not in note


class TestPolicyLevelSuppression:
    """Policy-level findings for suppressed statement indices are filtered out."""

    async def test_policy_level_findings_suppressed_for_full_wildcard_statement(self):
        """A policy-level finding from a check IN full_wildcard.supersedes is dropped."""

        from iam_validator.core.models import IAMPolicy

        # Build a minimal registry with full_wildcard enabled + a mock policy-level check
        registry = CheckRegistry(suppress_superseded=True)
        registry.register(FullWildcardCheck())
        registry.configure_check("full_wildcard", CheckConfig(check_id="full_wildcard", enabled=True))

        # Mock check reusing a check_id declared in FullWildcardCheck.supersedes,
        # emitting a policy-level finding for statement index 0
        async def _execute_policy(self_inner, policy, policy_file, fetcher, config, **kwargs):
            return [
                ValidationIssue(
                    severity="high",
                    statement_index=0,
                    issue_type="test_policy_level",
                    message="Policy-level issue for stmt 0",
                )
            ]

        cls = type(
            "_MockPolicyLevelCheck",
            (PolicyCheck,),
            {
                "check_id": "sensitive_action",
                "description": "Mock policy-level check",
                "default_severity": "high",
                "execute_policy": _execute_policy,
            },
        )
        registry.register(cls())
        registry.configure_check("sensitive_action", CheckConfig(check_id="sensitive_action", enabled=True))

        policy = IAMPolicy(Statement=[{"Effect": "Allow", "Action": "*", "Resource": "*"}])
        fetcher = _make_mock_fetcher()

        from iam_validator.core.policy_checks import _validate_policy_with_registry

        result = await _validate_policy_with_registry(
            policy=policy,
            policy_file="test.json",
            registry=registry,
            fetcher=fetcher,
            fail_on_severities=["error", "critical"],
        )

        check_ids = {i.check_id for i in result.issues}
        assert "full_wildcard" in check_ids
        assert "sensitive_action" not in check_ids

    async def test_policy_level_finding_not_in_supersedes_is_kept(self):
        """A policy-level finding from a check NOT in full_wildcard.supersedes stays."""

        from iam_validator.core.models import IAMPolicy

        registry = CheckRegistry(suppress_superseded=True)
        registry.register(FullWildcardCheck())
        registry.configure_check("full_wildcard", CheckConfig(check_id="full_wildcard", enabled=True))

        async def _execute_policy(self_inner, policy, policy_file, fetcher, config, **kwargs):
            return [
                ValidationIssue(
                    severity="high",
                    statement_index=0,
                    issue_type="test_policy_level",
                    message="Policy-level issue for stmt 0",
                )
            ]

        cls = type(
            "_MockNonSupersededPolicyCheck",
            (PolicyCheck,),
            {
                "check_id": "mock_policy_level",
                "description": "Mock policy-level check not declared in supersedes",
                "default_severity": "high",
                "execute_policy": _execute_policy,
            },
        )
        registry.register(cls())
        registry.configure_check("mock_policy_level", CheckConfig(check_id="mock_policy_level", enabled=True))

        policy = IAMPolicy(Statement=[{"Effect": "Allow", "Action": "*", "Resource": "*"}])
        fetcher = _make_mock_fetcher()

        from iam_validator.core.policy_checks import _validate_policy_with_registry

        result = await _validate_policy_with_registry(
            policy=policy,
            policy_file="test.json",
            registry=registry,
            fetcher=fetcher,
            fail_on_severities=["error", "critical"],
        )

        check_ids = {i.check_id for i in result.issues}
        assert "full_wildcard" in check_ids
        assert "mock_policy_level" in check_ids

    @pytest.mark.parametrize("suppress_superseded", [True, False])
    async def test_invalid_sid_format_reported_regardless_of_suppression(self, suppress_superseded):
        """sid_uniqueness is not in full_wildcard.supersedes: always reported."""
        from iam_validator.core.models import IAMPolicy

        registry = CheckRegistry(suppress_superseded=suppress_superseded)
        registry.register(FullWildcardCheck())
        registry.configure_check("full_wildcard", CheckConfig(check_id="full_wildcard", enabled=True))
        from iam_validator.checks.sid_uniqueness import SidUniquenessCheck

        registry.register(SidUniquenessCheck())
        registry.configure_check("sid_uniqueness", CheckConfig(check_id="sid_uniqueness", enabled=True))

        policy = IAMPolicy(
            Statement=[
                {"Sid": "bad-sid-with-dashes", "Effect": "Allow", "Action": "*", "Resource": "*"},
                {"Sid": "Benign", "Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},
            ]
        )
        fetcher = _make_mock_fetcher()

        from iam_validator.core.policy_checks import _validate_policy_with_registry

        result = await _validate_policy_with_registry(
            policy=policy,
            policy_file="test.json",
            registry=registry,
            fetcher=fetcher,
            fail_on_severities=["error", "critical"],
        )

        issue_types = {i.issue_type for i in result.issues}
        assert "invalid_sid_format" in issue_types

    async def test_policy_level_findings_kept_for_non_full_wildcard_statement(self):
        """Policy-level findings for non-*/* statement indices are kept."""
        from iam_validator.core.models import IAMPolicy

        registry = CheckRegistry(suppress_superseded=True)
        registry.register(FullWildcardCheck())
        registry.configure_check("full_wildcard", CheckConfig(check_id="full_wildcard", enabled=True))

        # Policy-level check emits for statement index 1 (not the */* statement at 0)
        async def _execute_policy(self_inner, policy, policy_file, fetcher, config, **kwargs):
            return [
                ValidationIssue(
                    severity="high",
                    statement_index=1,
                    issue_type="test_policy_level",
                    message="Policy-level issue for stmt 1",
                )
            ]

        cls = type(
            "_MockPolicyLevelCheck2",
            (PolicyCheck,),
            {
                "check_id": "mock_policy_level2",
                "description": "Mock policy-level check 2",
                "default_severity": "high",
                "execute_policy": _execute_policy,
            },
        )
        registry.register(cls())
        registry.configure_check("mock_policy_level2", CheckConfig(check_id="mock_policy_level2", enabled=True))

        policy = IAMPolicy(
            Statement=[
                {"Effect": "Allow", "Action": "*", "Resource": "*"},  # idx 0 — suppressed
                {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"},  # idx 1 — kept
            ]
        )
        fetcher = _make_mock_fetcher()

        from iam_validator.core.policy_checks import _validate_policy_with_registry

        result = await _validate_policy_with_registry(
            policy=policy,
            policy_file="test.json",
            registry=registry,
            fetcher=fetcher,
            fail_on_severities=["error", "critical"],
        )

        check_ids = {i.check_id for i in result.issues}
        assert "mock_policy_level2" in check_ids

    async def test_scp_full_wildcard_allow_produces_no_wildcard_action_finding(self):
        """Neither full_wildcard nor wildcard_action applies to SCPs; an SCP Allow */* reports neither."""
        from iam_validator.checks.wildcard_action import WildcardActionCheck
        from iam_validator.core.models import IAMPolicy

        registry = CheckRegistry(suppress_superseded=True)
        registry.register(FullWildcardCheck())
        registry.register(WildcardActionCheck())
        registry.configure_check("full_wildcard", CheckConfig(check_id="full_wildcard", enabled=True))
        registry.configure_check("wildcard_action", CheckConfig(check_id="wildcard_action", enabled=True))

        policy = IAMPolicy(Statement=[{"Effect": "Allow", "Action": "*", "Resource": "*"}])
        fetcher = _make_mock_fetcher()

        from iam_validator.core.policy_checks import _validate_policy_with_registry

        result = await _validate_policy_with_registry(
            policy=policy,
            policy_file="test.json",
            registry=registry,
            fetcher=fetcher,
            fail_on_severities=["error", "critical"],
            policy_type="SERVICE_CONTROL_POLICY",
        )

        check_ids = {i.check_id for i in result.issues}
        assert "wildcard_action" not in check_ids
        assert "full_wildcard" not in check_ids

    async def test_identity_policy_full_wildcard_allow_still_reports_wildcard_action(self):
        """The same */* Allow statement in an identity policy still reports wildcard_action."""
        from iam_validator.checks.wildcard_action import WildcardActionCheck
        from iam_validator.core.models import IAMPolicy

        registry = CheckRegistry(suppress_superseded=False)
        registry.register(WildcardActionCheck())
        registry.configure_check("wildcard_action", CheckConfig(check_id="wildcard_action", enabled=True))

        policy = IAMPolicy(Statement=[{"Effect": "Allow", "Action": "*", "Resource": "*"}])
        fetcher = _make_mock_fetcher()

        from iam_validator.core.policy_checks import _validate_policy_with_registry

        result = await _validate_policy_with_registry(
            policy=policy,
            policy_file="test.json",
            registry=registry,
            fetcher=fetcher,
            fail_on_severities=["error", "critical"],
            policy_type="IDENTITY_POLICY",
        )

        check_ids = {i.check_id for i in result.issues}
        assert "wildcard_action" in check_ids

    async def test_rcp_full_wildcard_allow_produces_no_wildcard_findings(self):
        """RCPFullAWSAccess is AWS's mandatory default RCP; an RCP Allow */* reports nothing."""
        from iam_validator.checks.wildcard_action import WildcardActionCheck
        from iam_validator.checks.wildcard_resource import WildcardResourceCheck
        from iam_validator.core.models import IAMPolicy

        registry = CheckRegistry(suppress_superseded=True)
        registry.register(FullWildcardCheck())
        registry.register(WildcardActionCheck())
        registry.register(WildcardResourceCheck())
        for check_id in ("full_wildcard", "wildcard_action", "wildcard_resource"):
            registry.configure_check(check_id, CheckConfig(check_id=check_id, enabled=True))

        policy = IAMPolicy(Statement=[{"Effect": "Allow", "Principal": "*", "Action": "*", "Resource": "*"}])
        fetcher = _make_mock_fetcher()

        from iam_validator.core.policy_checks import _validate_policy_with_registry

        result = await _validate_policy_with_registry(
            policy=policy,
            policy_file="test.json",
            registry=registry,
            fetcher=fetcher,
            fail_on_severities=["error", "critical"],
            policy_type="RESOURCE_CONTROL_POLICY",
        )

        assert result.issues == []

    async def test_rcp_narrow_resource_wildcard_action_produces_no_finding(self):
        from iam_validator.checks.wildcard_action import WildcardActionCheck
        from iam_validator.core.models import IAMPolicy

        registry = CheckRegistry(suppress_superseded=False)
        registry.register(WildcardActionCheck())
        registry.configure_check("wildcard_action", CheckConfig(check_id="wildcard_action", enabled=True))

        policy = IAMPolicy(
            Statement=[
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "*",
                    "Resource": "arn:aws:s3:::some-bucket",
                }
            ]
        )
        fetcher = _make_mock_fetcher()

        from iam_validator.core.policy_checks import _validate_policy_with_registry

        result = await _validate_policy_with_registry(
            policy=policy,
            policy_file="test.json",
            registry=registry,
            fetcher=fetcher,
            fail_on_severities=["error", "critical"],
            policy_type="RESOURCE_CONTROL_POLICY",
        )

        check_ids = {i.check_id for i in result.issues}
        assert "wildcard_action" not in check_ids

    async def test_scp_narrow_resource_wildcard_action_produces_no_finding(self):
        from iam_validator.checks.wildcard_action import WildcardActionCheck
        from iam_validator.core.models import IAMPolicy

        registry = CheckRegistry(suppress_superseded=False)
        registry.register(WildcardActionCheck())
        registry.configure_check("wildcard_action", CheckConfig(check_id="wildcard_action", enabled=True))

        policy = IAMPolicy(Statement=[{"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::some-bucket"}])
        fetcher = _make_mock_fetcher()

        from iam_validator.core.policy_checks import _validate_policy_with_registry

        result = await _validate_policy_with_registry(
            policy=policy,
            policy_file="test.json",
            registry=registry,
            fetcher=fetcher,
            fail_on_severities=["error", "critical"],
            policy_type="SERVICE_CONTROL_POLICY",
        )

        check_ids = {i.check_id for i in result.issues}
        assert "wildcard_action" not in check_ids

    @staticmethod
    def _boundary_registry(suppress: bool) -> CheckRegistry:
        from iam_validator.checks.policy_type_validation import PolicyTypeValidationCheck
        from iam_validator.checks.service_wildcard import ServiceWildcardCheck
        from iam_validator.checks.wildcard_action import WildcardActionCheck
        from iam_validator.checks.wildcard_resource import WildcardResourceCheck

        registry = CheckRegistry(suppress_superseded=suppress)
        for check in (
            FullWildcardCheck(),
            WildcardActionCheck(),
            WildcardResourceCheck(),
            ServiceWildcardCheck(),
            PolicyTypeValidationCheck(),
        ):
            registry.register(check)
            registry.configure_check(check.check_id, CheckConfig(check_id=check.check_id, enabled=True))
        return registry

    async def _run(self, statements, policy_type: str, suppress: bool):
        from iam_validator.core.models import IAMPolicy
        from iam_validator.core.policy_checks import _validate_policy_with_registry

        return await _validate_policy_with_registry(
            policy=IAMPolicy(Statement=statements),
            policy_file="test.json",
            registry=self._boundary_registry(suppress),
            fetcher=_make_mock_fetcher(),
            fail_on_severities=["error", "critical"],
            policy_type=policy_type,
        )

    @pytest.mark.parametrize("suppress", [True, False])
    async def test_rcp_full_aws_access_clean(self, suppress):
        result = await self._run(
            [{"Sid": "RCPFullAWSAccess", "Effect": "Allow", "Principal": "*", "Action": "*", "Resource": "*"}],
            "RESOURCE_CONTROL_POLICY",
            suppress,
        )
        assert result.issues == []

    @pytest.mark.parametrize("suppress", [True, False])
    async def test_scp_full_aws_access_clean(self, suppress):
        result = await self._run(
            [{"Sid": "FullAWSAccess", "Effect": "Allow", "Action": "*", "Resource": "*"}],
            "SERVICE_CONTROL_POLICY",
            suppress,
        )
        assert result.issues == []

    @pytest.mark.parametrize("suppress", [True, False])
    async def test_rcp_wildcard_shaped_allow_without_principal_still_reported(self, suppress):
        """full_wildcard is excluded from RCPs, so it must not mask policy-level RCP findings."""
        result = await self._run(
            [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
            "RESOURCE_CONTROL_POLICY",
            suppress,
        )
        issue_types = {i.issue_type for i in result.issues}
        assert "invalid_rcp_effect" in issue_types
        assert "invalid_rcp_wildcard_action" in issue_types

    @pytest.mark.parametrize("suppress", [True, False])
    async def test_rcp_narrow_resource_allow_still_reported(self, suppress):
        result = await self._run(
            [{"Effect": "Allow", "Principal": "*", "Action": "*", "Resource": "arn:aws:s3:::my-bucket"}],
            "RESOURCE_CONTROL_POLICY",
            suppress,
        )
        assert "invalid_rcp_effect" in {i.issue_type for i in result.issues}

    @pytest.mark.parametrize("suppress", [True, False])
    async def test_identity_policy_full_wildcard_suppression_unchanged(self, suppress):
        """The gate must not disturb identity policies, where full_wildcard does apply."""
        result = await self._run(
            [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
            "IDENTITY_POLICY",
            suppress,
        )
        check_ids = {i.check_id for i in result.issues}
        assert "full_wildcard" in check_ids
        assert ("wildcard_action" in check_ids) is not suppress


def _issue(check_id: str) -> ValidationIssue:
    return ValidationIssue(
        severity="medium",
        statement_index=0,
        issue_type=f"{check_id}_finding",
        message="m",
        check_id=check_id,
    )


class Dominant(PolicyCheck):
    check_id: ClassVar[str] = "dominant"
    description: ClassVar[str] = "supersedes only 'subsumed'"
    supersedes: ClassVar[frozenset[str]] = frozenset({"subsumed"})

    async def execute(self, statement, statement_idx, fetcher, config):
        return [_issue("dominant")]


def test_supersedes_only_suppresses_declared_ids():
    registry = CheckRegistry()
    statement = Statement(effect="Allow", action=["*"], resource=["*"])
    issues_map = {
        "dominant": [_issue("dominant")],
        "subsumed": [_issue("subsumed")],
        "unrelated": [_issue("unrelated")],
    }

    result = registry._apply_supersedes(statement, [Dominant()], issues_map)

    assert set(result) == {"dominant", "unrelated"}
    assert "1 checks suppressed" in result["dominant"][0].message
    assert "subsumed" in result["dominant"][0].message
    assert "unrelated" not in result["dominant"][0].message
