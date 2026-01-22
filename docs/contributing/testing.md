---
title: Testing
description: Run and write tests
---

# Testing

How to run and write tests for IAM Policy Validator.

## Running Tests

### All Tests

```bash
uv run pytest
```

### Specific Test File

```bash
uv run pytest tests/test_specific.py -v
```

### Pattern Matching

```bash
uv run pytest -k "wildcard" -v
```

### Skip Slow Tests

```bash
uv run pytest -m "not slow"
```

### Skip Benchmarks

```bash
uv run pytest -m "not benchmark"
```

### With Coverage

```bash
uv run pytest --cov=iam_validator --cov-report=html
open htmlcov/index.html
```

## Test Structure

Tests mirror the source structure:

```
tests/
├── conftest.py              # Shared fixtures
├── test_policy_loader.py    # Tests for policy_loader.py
├── checks/
│   ├── test_wildcard_action.py
│   └── test_sensitive_action.py
└── commands/
    └── test_validate.py
```

## Writing Tests

### Basic Test

```python
import pytest
from iam_validator.checks.wildcard_action import WildcardActionCheck


@pytest.mark.asyncio
async def test_wildcard_action_detected():
    check = WildcardActionCheck()

    statement = Statement(
        effect="Allow",
        action="*",
        resource="*",
    )

    issues = await check.execute(statement, 0, mock_fetcher, config)

    assert len(issues) == 1
    assert issues[0].severity == "medium"
```

### Using Fixtures

```python
# conftest.py
import pytest
from iam_validator.core.models import Statement


@pytest.fixture
def allow_statement():
    return Statement(
        effect="Allow",
        action=["s3:GetObject"],
        resource="arn:aws:s3:::bucket/*",
    )


# test_my_check.py
@pytest.mark.asyncio
async def test_with_fixture(allow_statement):
    issues = await check.execute(allow_statement, 0, fetcher, config)
    assert len(issues) == 0
```

### Mocking AWS Fetcher

```python
from unittest.mock import AsyncMock


@pytest.fixture
def mock_fetcher():
    fetcher = AsyncMock()
    fetcher.validate_action.return_value = (True, None, False)
    fetcher.expand_wildcard_action.return_value = ["s3:GetObject"]
    return fetcher
```

### Test Policies

Use policies from `examples/iam-test-policies/`:

```python
import json
from pathlib import Path


def load_test_policy(name: str) -> dict:
    path = Path("examples/iam-test-policies") / name
    return json.loads(path.read_text())


@pytest.mark.asyncio
async def test_with_real_policy():
    policy = load_test_policy("wildcard-action.json")
    # Test against real policy
```

## Test Markers

| Marker                     | Usage                   |
| -------------------------- | ----------------------- |
| `@pytest.mark.asyncio`     | Async tests             |
| `@pytest.mark.slow`        | Long-running tests      |
| `@pytest.mark.benchmark`   | Performance tests       |
| `@pytest.mark.integration` | External resource tests |

```python
@pytest.mark.slow
@pytest.mark.asyncio
async def test_full_validation():
    # This test takes a while
    pass
```

## Test Configuration

See `pyproject.toml`:

```toml
[tool.pytest.ini_options]
testpaths = ["tests"]
asyncio_mode = "auto"
markers = [
    "benchmark: marks tests as benchmarks",
    "slow: marks tests as slow",
    "integration: marks tests as integration tests",
]
```

## Coverage Goals

- Aim for >80% coverage on core modules
- All checks should have tests for pass/fail cases
- Edge cases should be tested

Check coverage:

```bash
uv run pytest --cov=iam_validator --cov-report=term-missing
```
