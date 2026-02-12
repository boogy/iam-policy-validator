# Tests Module - Testing Patterns and Guidelines

**Purpose**: Test suite for IAM Policy Validator
**Parent Context**: Extends [../CLAUDE.md](../CLAUDE.md)

---

## Test Structure

```
tests/
├── checks/                    # Check-specific tests
│   ├── conftest.py           # Shared fixtures (mock_fetcher, configs)
│   ├── test_action_validation_check.py
│   ├── test_wildcard_action_check.py
│   ├── test_sensitive_action_*.py
│   └── ...
├── commands/                  # CLI command tests
│   ├── test_query_command.py
│   └── test_completion_command.py
├── core/                      # Core module tests
│   ├── conftest.py           # Shared fixtures for core tests
│   ├── test_check_registry.py
│   ├── test_models.py
│   ├── test_policy_loader.py
│   ├── test_pr_commenter_diff_filtering.py  # PR diff filtering + off-diff pipeline
│   ├── test_finding_fingerprint.py
│   └── ...
├── config/                    # Configuration tests
│   └── test_config_loader.py
├── mcp/                       # MCP server tests
│   ├── test_validation_tools.py
│   ├── test_generation_tools.py
│   └── test_org_config.py
└── integrations/              # GitHub integration tests
    ├── test_github_pagination.py
    ├── test_label_manager.py
    └── test_comment_deduplication.py
```

---

## Running Tests

```bash
# Run all tests
uv run pytest

# Run specific file
uv run pytest tests/checks/test_wildcard_action_check.py

# Run tests matching pattern
uv run pytest -k "wildcard"
uv run pytest -k "test_detects"

# Run specific test
uv run pytest tests/checks/test_wildcard_action_check.py::test_detects_wildcard_action

# Skip slow/benchmark tests
uv run pytest -m "not slow"
uv run pytest -m "not benchmark"

# Run only integration tests
uv run pytest -m integration

# With coverage
uv run pytest --cov=iam_validator --cov-report=html
uv run pytest --cov=iam_validator --cov-report=term-missing

# Verbose output
uv run pytest -v --tb=long
```

---

## Test Markers

```python
import pytest

@pytest.mark.benchmark
def test_performance():
    """Performance benchmark - skipped with -m 'not benchmark'"""
    pass

@pytest.mark.slow
def test_expensive_operation():
    """Long-running test - skipped with -m 'not slow'"""
    pass

@pytest.mark.integration
def test_aws_api():
    """Requires external resources - skipped with -m 'not integration'"""
    pass
```

---

## Common Fixtures

### Mock AWS Service Fetcher

```python
import pytest
from unittest.mock import AsyncMock, MagicMock

@pytest.fixture
def mock_fetcher():
    """Mock AWSServiceFetcher for tests."""
    fetcher = MagicMock()

    # Mock validate_action
    fetcher.validate_action = AsyncMock(
        return_value=(True, None, False)  # (is_valid, error, is_wildcard)
    )

    # Mock expand_wildcard_action
    fetcher.expand_wildcard_action = AsyncMock(
        return_value=["s3:GetObject", "s3:GetObjectAcl"]
    )

    # Mock fetch_service_by_name
    fetcher.fetch_service_by_name = AsyncMock(
        return_value=MagicMock(
            actions=["GetObject", "PutObject"],
            condition_keys=["s3:x-amz-acl"],
        )
    )

    return fetcher
```

### Check Configuration

```python
from iam_validator.core.check_registry import CheckConfig

@pytest.fixture
def default_config():
    """Default check configuration."""
    return CheckConfig(
        check_id="test_check",
        enabled=True,
    )

@pytest.fixture
def custom_config():
    """Config with overrides."""
    return CheckConfig(
        check_id="test_check",
        enabled=True,
        severity="critical",
        config={
            "custom_option": "value",
            "message": "Custom message",
        },
    )
```

### Test Statements

```python
from iam_validator.core.models import Statement

@pytest.fixture
def allow_all_statement():
    """Statement that allows everything."""
    return Statement(
        effect="Allow",
        action=["*"],
        resource=["*"],
    )

@pytest.fixture
def readonly_statement():
    """Read-only statement."""
    return Statement(
        effect="Allow",
        action=["s3:GetObject", "s3:ListBucket"],
        resource=["arn:aws:s3:::my-bucket/*"],
        sid="ReadOnlyAccess",
    )

@pytest.fixture
def statement_with_condition():
    """Statement with condition."""
    return Statement(
        effect="Allow",
        action=["s3:GetObject"],
        resource=["*"],
        condition={
            "StringEquals": {
                "aws:SourceVpc": "vpc-12345"
            }
        },
    )
```

### Test Policies

```python
from iam_validator.core.models import IAMPolicy

@pytest.fixture
def simple_policy():
    """Simple valid policy."""
    return IAMPolicy(
        version="2012-10-17",
        statement=[
            Statement(
                effect="Allow",
                action=["s3:GetObject"],
                resource=["arn:aws:s3:::my-bucket/*"],
            )
        ],
    )

@pytest.fixture
def policy_with_multiple_statements():
    """Policy with multiple statements."""
    return IAMPolicy(
        version="2012-10-17",
        statement=[
            Statement(effect="Allow", action=["s3:GetObject"], resource=["*"]),
            Statement(effect="Deny", action=["s3:DeleteBucket"], resource=["*"]),
        ],
    )
```

---

## Test Patterns

### Testing a Check

```python
import pytest
from iam_validator.checks.wildcard_action import WildcardActionCheck
from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.models import Statement

class TestWildcardActionCheck:
    """Tests for WildcardActionCheck."""

    @pytest.fixture
    def check(self):
        return WildcardActionCheck()

    @pytest.fixture
    def config(self):
        return CheckConfig(check_id="wildcard_action", enabled=True)

    @pytest.mark.asyncio
    async def test_detects_wildcard_action(self, check, config, mock_fetcher):
        """Should detect Action: '*'."""
        statement = Statement(effect="Allow", action=["*"], resource=["*"])

        issues = await check.execute(statement, 0, mock_fetcher, config)

        assert len(issues) == 1
        assert issues[0].issue_type == "overly_permissive"
        assert issues[0].severity == "medium"

    @pytest.mark.asyncio
    async def test_ignores_deny_statements(self, check, config, mock_fetcher):
        """Should not flag Deny statements."""
        statement = Statement(effect="Deny", action=["*"], resource=["*"])

        issues = await check.execute(statement, 0, mock_fetcher, config)

        assert len(issues) == 0

    @pytest.mark.asyncio
    async def test_respects_severity_override(self, check, mock_fetcher):
        """Should use severity from config."""
        config = CheckConfig(
            check_id="wildcard_action",
            enabled=True,
            severity="critical",
        )
        statement = Statement(effect="Allow", action=["*"], resource=["*"])

        issues = await check.execute(statement, 0, mock_fetcher, config)

        assert issues[0].severity == "critical"
```

### Testing a Policy-Level Check

```python
import pytest
from iam_validator.checks.sid_uniqueness import SidUniquenessCheck
from iam_validator.core.models import IAMPolicy, Statement

class TestSidUniquenessCheck:
    """Tests for SidUniquenessCheck."""

    @pytest.fixture
    def check(self):
        return SidUniquenessCheck()

    @pytest.mark.asyncio
    async def test_detects_duplicate_sids(self, check, config, mock_fetcher):
        """Should detect duplicate SIDs."""
        policy = IAMPolicy(
            version="2012-10-17",
            statement=[
                Statement(effect="Allow", action=["s3:GetObject"], resource=["*"], sid="DuplicateSid"),
                Statement(effect="Allow", action=["s3:PutObject"], resource=["*"], sid="DuplicateSid"),
            ],
        )

        issues = await check.execute_policy(policy, "test.json", mock_fetcher, config)

        assert len(issues) == 1
        assert "duplicate" in issues[0].message.lower()
```

---

## Parameterized Tests

```python
import pytest

@pytest.mark.parametrize("action,expected_valid", [
    ("s3:GetObject", True),
    ("s3:InvalidAction", False),
    ("invalid:action", False),
    ("*", True),  # Wildcard is valid syntax
])
@pytest.mark.asyncio
async def test_action_validation(action, expected_valid, mock_fetcher):
    """Test action validation with various inputs."""
    mock_fetcher.validate_action.return_value = (expected_valid, None, False)

    is_valid, error, _ = await mock_fetcher.validate_action(action)

    assert is_valid == expected_valid
```

---

## Mocking Patterns

### Mock HTTP Response

```python
from unittest.mock import patch, AsyncMock
import httpx

@pytest.mark.asyncio
async def test_fetches_service_data():
    mock_response = AsyncMock()
    mock_response.json.return_value = {
        "servicePrefix": "s3",
        "actions": [{"name": "GetObject"}],
    }
    mock_response.status_code = 200

    with patch("httpx.AsyncClient.get", return_value=mock_response):
        async with AWSServiceFetcher() as fetcher:
            service = await fetcher.fetch_service_by_name("s3")

        assert service.service_prefix == "s3"
```

### Mock File System

```python
from unittest.mock import mock_open, patch

def test_reads_policy_file():
    policy_json = '{"Version": "2012-10-17", "Statement": []}'

    with patch("builtins.open", mock_open(read_data=policy_json)):
        # Test code that reads files
        pass
```

---

## Test File Naming

| Source File                 | Test File                                    |
| --------------------------- | -------------------------------------------- |
| `checks/wildcard_action.py` | `tests/checks/test_wildcard_action_check.py` |
| `core/models.py`            | `tests/core/test_models.py`                  |
| `commands/validate.py`      | `tests/commands/test_validate_command.py`    |

---

## Quick Search

```bash
# Find tests for specific feature
rg -n "test.*wildcard" .

# Find fixture definitions
rg -n "@pytest.fixture" .

# Find async tests
rg -n "@pytest.mark.asyncio" .

# Find parameterized tests
rg -n "@pytest.mark.parametrize" .

# Find tests using specific mock
rg -n "mock_fetcher" .
```
