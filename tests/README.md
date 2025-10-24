# Test Suite

## Overview

This directory contains unit tests for the IAM Policy Validator.

## Test Files

### ✅ `test_action_condition_enforcement.py` - 13 Tests (ALL PASSING)

Comprehensive tests for the `ActionConditionEnforcementCheck` class, covering:

- **none_of for actions** - Detecting forbidden actions
- **none_of for conditions** - Preventing dangerous conditions
- **all_of logic** - Requiring all specified conditions
- **any_of logic** - Requiring at least one condition
- **Combined logic** - Using multiple operators together
- **Edge cases** - Deny statements, empty configs, etc.

## Running Tests

### Run All Tests
```bash
uv run pytest tests/ -v
```

### Run Specific Test File
```bash
uv run pytest tests/test_action_condition_enforcement.py -v
```

### Run Specific Test
```bash
uv run pytest tests/test_action_condition_enforcement.py::TestActionConditionEnforcement::test_none_of_actions_forbidden -v
```

### Run with Coverage
```bash
uv run pytest tests/ --cov=iam_validator --cov-report=html
```

## Test Results

```
======================== 13 passed, 6 warnings in 0.08s ========================

tests/test_action_condition_enforcement.py::TestActionConditionEnforcement::test_check_id PASSED
tests/test_action_condition_enforcement.py::TestActionConditionEnforcement::test_description PASSED
tests/test_action_condition_enforcement.py::TestActionConditionEnforcement::test_none_of_actions_forbidden PASSED
tests/test_action_condition_enforcement.py::TestActionConditionEnforcement::test_none_of_actions_allowed PASSED
tests/test_action_condition_enforcement.py::TestActionConditionEnforcement::test_none_of_conditions_forbidden PASSED
tests/test_action_condition_enforcement.py::TestActionConditionEnforcement::test_none_of_conditions_allowed PASSED
tests/test_action_condition_enforcement.py::TestActionConditionEnforcement::test_all_of_conditions_missing PASSED
tests/test_action_condition_enforcement.py::TestActionConditionEnforcement::test_all_of_conditions_present PASSED
tests/test_action_condition_enforcement.py::TestActionConditionEnforcement::test_any_of_conditions_missing_all PASSED
tests/test_action_condition_enforcement.py::TestActionConditionEnforcement::test_any_of_conditions_one_present PASSED
tests/test_action_condition_enforcement.py::TestActionConditionEnforcement::test_deny_statements_ignored PASSED
tests/test_action_condition_enforcement.py::TestActionConditionEnforcement::test_simple_required_condition PASSED
tests/test_action_condition_enforcement.py::TestActionConditionEnforcement::test_combined_all_of_and_none_of PASSED
```

## Adding New Tests

1. Create a new test file: `test_<component>.py`
2. Import pytest and the component to test
3. Create a test class: `class Test<Component>:`
4. Add test methods: `def test_<scenario>(self):`
5. Use `@pytest.mark.asyncio` for async tests
6. Run tests to verify they pass

## Test Structure

```python
import pytest
from iam_validator.checks.action_condition_enforcement import ActionConditionEnforcementCheck
from iam_validator.core.check_registry import CheckConfig
from iam_validator.core.models import Statement

class TestActionConditionEnforcement:
    @pytest.fixture
    def check(self):
        return ActionConditionEnforcementCheck()

    @pytest.mark.asyncio
    async def test_something(self, check):
        config = CheckConfig(...)
        statement = Statement(...)
        issues = await check.execute(statement, 0, None, config)
        assert len(issues) == 0
```

## Notes

- Tests use `pytest` with `pytest-asyncio` for async support
- Mock fetcher (None) used to avoid AWS API calls
- Tests are fast (< 0.1s total) and isolated
- All tests should be independent and repeatable
