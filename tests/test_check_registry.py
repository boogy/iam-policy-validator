"""Unit tests for Check Registry module."""

from unittest.mock import MagicMock

import pytest

from iam_validator.core.check_registry import (
    CheckConfig,
    CheckRegistry,
    PolicyCheck,
    create_default_registry,
)
from iam_validator.core.models import Statement, ValidationIssue


class MockCheck(PolicyCheck):
    """Mock check for testing."""

    def __init__(self, check_id="mock_check", desc="Mock check for testing"):
        self._check_id = check_id
        self._description = desc

    @property
    def check_id(self) -> str:
        return self._check_id

    @property
    def description(self) -> str:
        return self._description

    async def execute(self, statement, statement_idx, fetcher, config):
        """Return empty issues list."""
        return []


class FailingCheck(PolicyCheck):
    """Mock check that raises an exception."""

    @property
    def check_id(self) -> str:
        return "failing_check"

    @property
    def description(self) -> str:
        return "A check that fails"

    async def execute(self, statement, statement_idx, fetcher, config):
        """Raise an exception."""
        raise ValueError("Intentional failure for testing")


class IssueGeneratingCheck(PolicyCheck):
    """Mock check that generates validation issues."""

    def __init__(self, num_issues=1, check_id="issue_check"):
        self.num_issues = num_issues
        self._check_id = check_id

    @property
    def check_id(self) -> str:
        return self._check_id

    @property
    def description(self) -> str:
        return "Generates issues"

    async def execute(self, statement, statement_idx, fetcher, config):
        """Generate mock issues."""
        return [
            ValidationIssue(
                severity="warning",
                statement_index=statement_idx,
                issue_type="test_issue",
                message=f"Test issue {i}",
            )
            for i in range(self.num_issues)
        ]


class TestCheckConfig:
    """Test the CheckConfig dataclass."""

    def test_default_values(self):
        """Test CheckConfig with default values."""
        config = CheckConfig(check_id="test_check")

        assert config.check_id == "test_check"
        assert config.enabled is True
        assert config.severity is None
        assert config.config == {}
        assert config.description == ""

    def test_custom_values(self):
        """Test CheckConfig with custom values."""
        custom_config = {"threshold": 10, "mode": "strict"}
        config = CheckConfig(
            check_id="test_check",
            enabled=False,
            severity="error",
            config=custom_config,
            description="A test check",
        )

        assert config.check_id == "test_check"
        assert config.enabled is False
        assert config.severity == "error"
        assert config.config == custom_config
        assert config.description == "A test check"


class TestPolicyCheck:
    """Test the PolicyCheck abstract base class."""

    def test_cannot_instantiate_abstract_class(self):
        """Test that PolicyCheck cannot be instantiated directly."""
        with pytest.raises(TypeError):
            PolicyCheck()

    def test_mock_check_implementation(self):
        """Test that MockCheck properly implements PolicyCheck."""
        check = MockCheck()

        assert check.check_id == "mock_check"
        assert check.description == "Mock check for testing"
        assert check.default_severity == "warning"

    def test_get_severity_default(self):
        """Test get_severity returns default when no override."""
        check = MockCheck()
        config = CheckConfig(check_id="mock_check")

        severity = check.get_severity(config)
        assert severity == "warning"

    def test_get_severity_override(self):
        """Test get_severity returns config override."""
        check = MockCheck()
        config = CheckConfig(check_id="mock_check", severity="error")

        severity = check.get_severity(config)
        assert severity == "error"


class TestCheckRegistry:
    """Test the CheckRegistry class."""

    @pytest.fixture
    def registry(self):
        """Create a fresh CheckRegistry instance."""
        return CheckRegistry()

    @pytest.fixture
    def mock_statement(self):
        """Create a mock IAM statement."""
        return Statement(effect="Allow", action=["s3:GetObject"], resource="arn:aws:s3:::bucket/*")

    @pytest.fixture
    def mock_fetcher(self):
        """Create a mock AWS service fetcher."""
        return MagicMock()

    def test_initialization_default(self):
        """Test CheckRegistry initialization with defaults."""
        registry = CheckRegistry()

        assert registry._checks == {}
        assert registry._configs == {}
        assert registry.enable_parallel is True

    def test_initialization_disable_parallel(self):
        """Test CheckRegistry initialization with parallel disabled."""
        registry = CheckRegistry(enable_parallel=False)

        assert registry.enable_parallel is False

    def test_register_check(self, registry):
        """Test registering a check."""
        check = MockCheck()
        registry.register(check)

        assert "mock_check" in registry._checks
        assert registry._checks["mock_check"] is check
        assert "mock_check" in registry._configs

    def test_register_multiple_checks(self, registry):
        """Test registering multiple checks."""
        check1 = MockCheck(check_id="check1")
        check2 = MockCheck(check_id="check2")

        registry.register(check1)
        registry.register(check2)

        assert len(registry._checks) == 2
        assert "check1" in registry._checks
        assert "check2" in registry._checks

    def test_unregister_check(self, registry):
        """Test unregistering a check."""
        check = MockCheck()
        registry.register(check)
        assert "mock_check" in registry._checks

        registry.unregister("mock_check")
        assert "mock_check" not in registry._checks
        assert "mock_check" not in registry._configs

    def test_unregister_nonexistent_check(self, registry):
        """Test unregistering a check that doesn't exist (should not raise error)."""
        registry.unregister("nonexistent_check")  # Should not raise

    def test_configure_check(self, registry):
        """Test configuring a registered check."""
        check = MockCheck()
        registry.register(check)

        new_config = CheckConfig(check_id="mock_check", enabled=False, severity="error")
        registry.configure_check("mock_check", new_config)

        config = registry.get_config("mock_check")
        assert config.enabled is False
        assert config.severity == "error"

    def test_configure_unregistered_check_raises_error(self, registry):
        """Test that configuring an unregistered check raises ValueError."""
        config = CheckConfig(check_id="unregistered")

        with pytest.raises(ValueError, match="not registered"):
            registry.configure_check("unregistered", config)

    def test_get_all_checks(self, registry):
        """Test getting all registered checks."""
        check1 = MockCheck(check_id="check1")
        check2 = MockCheck(check_id="check2")

        registry.register(check1)
        registry.register(check2)

        all_checks = registry.get_all_checks()
        assert len(all_checks) == 2
        assert check1 in all_checks
        assert check2 in all_checks

    def test_get_enabled_checks_all_enabled(self, registry):
        """Test getting enabled checks when all are enabled."""
        check1 = MockCheck(check_id="check1")
        check2 = MockCheck(check_id="check2")

        registry.register(check1)
        registry.register(check2)

        enabled = registry.get_enabled_checks()
        assert len(enabled) == 2

    def test_get_enabled_checks_some_disabled(self, registry):
        """Test getting enabled checks when some are disabled."""
        check1 = MockCheck(check_id="check1")
        check2 = MockCheck(check_id="check2")

        registry.register(check1)
        registry.register(check2)

        # Disable check1
        registry.configure_check("check1", CheckConfig(check_id="check1", enabled=False))

        enabled = registry.get_enabled_checks()
        assert len(enabled) == 1
        assert check2 in enabled
        assert check1 not in enabled

    def test_get_check(self, registry):
        """Test getting a specific check by ID."""
        check = MockCheck()
        registry.register(check)

        retrieved = registry.get_check("mock_check")
        assert retrieved is check

    def test_get_check_nonexistent(self, registry):
        """Test getting a non-existent check returns None."""
        result = registry.get_check("nonexistent")
        assert result is None

    def test_get_config(self, registry):
        """Test getting configuration for a check."""
        check = MockCheck()
        registry.register(check)

        config = registry.get_config("mock_check")
        assert config is not None
        assert config.check_id == "mock_check"

    def test_get_config_nonexistent(self, registry):
        """Test getting config for non-existent check returns None."""
        config = registry.get_config("nonexistent")
        assert config is None

    def test_is_enabled(self, registry):
        """Test checking if a check is enabled."""
        check = MockCheck()
        registry.register(check)

        assert registry.is_enabled("mock_check") is True

        # Disable it
        registry.configure_check("mock_check", CheckConfig(check_id="mock_check", enabled=False))
        assert registry.is_enabled("mock_check") is False

    def test_is_enabled_nonexistent(self, registry):
        """Test is_enabled for non-existent check returns False."""
        assert registry.is_enabled("nonexistent") is False

    def test_list_checks(self, registry):
        """Test listing all checks with their info."""
        check1 = MockCheck(check_id="check1", desc="First check")
        check2 = MockCheck(check_id="check2", desc="Second check")

        registry.register(check1)
        registry.register(check2)

        # Disable check2 and set custom severity
        registry.configure_check(
            "check2", CheckConfig(check_id="check2", enabled=False, severity="error")
        )

        checks_list = registry.list_checks()

        assert len(checks_list) == 2
        assert any(c["check_id"] == "check1" and c["enabled"] is True for c in checks_list)
        assert any(c["check_id"] == "check2" and c["enabled"] is False for c in checks_list)
        assert any(c["severity"] == "error" and c["check_id"] == "check2" for c in checks_list)

    @pytest.mark.asyncio
    async def test_execute_checks_parallel_no_checks(self, registry, mock_statement, mock_fetcher):
        """Test parallel execution with no checks registered."""
        issues = await registry.execute_checks_parallel(mock_statement, 0, mock_fetcher)
        assert issues == []

    @pytest.mark.asyncio
    async def test_execute_checks_parallel_with_issues(
        self, registry, mock_statement, mock_fetcher
    ):
        """Test parallel execution that generates issues."""
        check = IssueGeneratingCheck(num_issues=2)
        registry.register(check)

        issues = await registry.execute_checks_parallel(mock_statement, 0, mock_fetcher)

        assert len(issues) == 2
        assert all(isinstance(i, ValidationIssue) for i in issues)

    @pytest.mark.asyncio
    async def test_execute_checks_parallel_with_failing_check(
        self, registry, mock_statement, mock_fetcher
    ):
        """Test parallel execution handles failing checks gracefully."""
        failing = FailingCheck()
        working = IssueGeneratingCheck(num_issues=1)

        registry.register(failing)
        registry.register(working)

        # Should not raise, but continue with working check
        issues = await registry.execute_checks_parallel(mock_statement, 0, mock_fetcher)

        # Should still get issues from working check
        assert len(issues) == 1

    @pytest.mark.asyncio
    async def test_execute_checks_parallel_disabled_checks_skipped(
        self, registry, mock_statement, mock_fetcher
    ):
        """Test that disabled checks are not executed."""
        check1 = IssueGeneratingCheck(num_issues=1, check_id="issue_check")
        check2 = IssueGeneratingCheck(num_issues=1, check_id="issue_check2")

        registry.register(check1)
        registry.register(check2)

        # Disable check1
        registry.configure_check("issue_check", CheckConfig(check_id="issue_check", enabled=False))

        issues = await registry.execute_checks_parallel(mock_statement, 0, mock_fetcher)

        # Should only get issues from check2
        assert len(issues) == 1

    @pytest.mark.asyncio
    async def test_execute_checks_sequential(self, registry, mock_statement, mock_fetcher):
        """Test sequential execution of checks."""
        check = IssueGeneratingCheck(num_issues=2)
        registry.register(check)

        issues = await registry.execute_checks_sequential(mock_statement, 0, mock_fetcher)

        assert len(issues) == 2

    @pytest.mark.asyncio
    async def test_execute_checks_sequential_handles_failures(
        self, registry, mock_statement, mock_fetcher
    ):
        """Test sequential execution handles failures gracefully."""
        failing = FailingCheck()
        working = IssueGeneratingCheck(num_issues=1)

        registry.register(failing)
        registry.register(working)

        issues = await registry.execute_checks_sequential(mock_statement, 0, mock_fetcher)

        # Should still get issues from working check
        assert len(issues) == 1

    @pytest.mark.asyncio
    async def test_parallel_disabled_falls_back_to_sequential(self, mock_statement, mock_fetcher):
        """Test that parallel=False uses sequential execution."""
        registry = CheckRegistry(enable_parallel=False)
        check = IssueGeneratingCheck(num_issues=1)
        registry.register(check)

        issues = await registry.execute_checks_parallel(mock_statement, 0, mock_fetcher)

        assert len(issues) == 1

    @pytest.mark.asyncio
    async def test_single_check_uses_sequential(self, mock_statement, mock_fetcher):
        """Test that single check uses sequential even with parallel enabled."""
        registry = CheckRegistry(enable_parallel=True)
        check = IssueGeneratingCheck(num_issues=1)
        registry.register(check)

        issues = await registry.execute_checks_parallel(mock_statement, 0, mock_fetcher)

        assert len(issues) == 1


class TestCreateDefaultRegistry:
    """Test the create_default_registry factory function."""

    def test_create_default_registry_with_builtin_checks(self):
        """Test creating registry with built-in checks."""
        registry = create_default_registry(enable_parallel=True, include_builtin_checks=True)

        assert isinstance(registry, CheckRegistry)
        assert registry.enable_parallel is True
        # Should have built-in checks registered
        assert len(registry.get_all_checks()) > 0

    def test_create_default_registry_without_builtin_checks(self):
        """Test creating empty registry without built-in checks."""
        registry = create_default_registry(enable_parallel=True, include_builtin_checks=False)

        assert isinstance(registry, CheckRegistry)
        assert len(registry.get_all_checks()) == 0

    def test_create_default_registry_parallel_disabled(self):
        """Test creating registry with parallel execution disabled."""
        registry = create_default_registry(enable_parallel=False, include_builtin_checks=False)

        assert registry.enable_parallel is False
