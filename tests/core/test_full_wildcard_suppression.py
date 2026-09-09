"""Integration tests for full-wildcard suppression (suppress_superseded_findings)."""

from typing import ClassVar
from unittest.mock import AsyncMock, MagicMock

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
        """Policy-level findings referencing a */* statement index are dropped."""

        from iam_validator.core.models import IAMPolicy

        # Build a minimal registry with full_wildcard enabled + a mock policy-level check
        registry = CheckRegistry(suppress_superseded=True)
        registry.register(FullWildcardCheck())
        registry.configure_check("full_wildcard", CheckConfig(check_id="full_wildcard", enabled=True))

        # Add a mock policy-level check that emits a finding for statement index 0
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
                "check_id": "mock_policy_level",
                "description": "Mock policy-level check",
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
        assert "mock_policy_level" not in check_ids

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
