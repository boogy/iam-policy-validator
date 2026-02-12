---
description: Run tests for a specific check
---

You are running tests for a specific IAM policy check.

Given the check name argument: $ARGUMENTS

Steps:

1. **Parse the check name**:

   - If argument provided, use it as the check name
   - If no argument, list available checks and ask which to test

2. **Find related test files**:

   ```bash
   # Find test files for this check
   find tests/ -name "*$ARGUMENTS*" -type f
   ```

3. **Run the tests**:

   ```bash
   uv run pytest tests/checks/test_{check_name}_check.py -v --tb=short
   ```

4. **If tests fail**:

   - Show the failure details
   - Offer to help fix the failing tests
   - Show the relevant source code

5. **Run with coverage** (optional):

   ```bash
   uv run pytest tests/checks/test_{check_name}_check.py -v --cov=iam_validator/checks/{check_name}.py --cov-report=term-missing
   ```

6. **Additional test options**:
   - `-k "pattern"` - Run tests matching pattern
   - `--pdb` - Drop into debugger on failure
   - `-x` - Stop on first failure

Example usage:

- `/test-check wildcard_action`
- `/test-check sensitive_action`
- `/test-check` (will list available checks)
