---
name: add-check
description: Scaffold a new IAM policy validation check with proper structure, tests, and registration. Use when the user wants to add a new check, create a new validation rule, scaffold a check, or implement a new policy check. Triggers on "/add-check", "add a new check", "create a new validation check", or "scaffold a check".
---

# Add Check

Scaffold a new IAM policy validation check end-to-end.

## Workflow

Given the check name argument: $ARGUMENTS

### 1. Parse Check Name

- Convert to snake_case for `check_id` (e.g., `my_check`)
- Convert to PascalCase for class name (e.g., `MyCheck`)
- If no argument, ask for: check name, description, severity

### 2. Ask Clarifying Questions

- What does this check validate?
- What severity level? (low, medium, high, critical, error, warning)
- What check type?
  - **Statement-level** (`execute`) — runs per statement. For individual actions, resources, conditions.
  - **Policy-level** (`execute_policy`) — runs per policy. For cross-statement validation, aggregate analysis, policy-wide constraints.
  - **Combined** (both) — for checks needing both per-statement AND policy-wide analysis.
- What `issue_type` category? (e.g., `overly_permissive`, `invalid_action`, `policy_structure`)

### 3. Create Check File

Create `iam_validator/checks/{check_name}.py` using the appropriate template from [references/templates.md](references/templates.md).

### 4. Update Imports

Add to `iam_validator/checks/__init__.py`:

```python
from iam_validator.checks.{check_name} import {CheckName}Check
# Add "{CheckName}Check" to __all__
```

### 5. Register the Check

Add to `iam_validator/core/check_registry.py` in `create_default_registry()`:

```python
registry.register(checks.{CheckName}Check())
```

### 6. Create Test File

Create `tests/checks/test_{check_name}_check.py` using the appropriate test template from [references/templates.md](references/templates.md).

### 7. Verify

```bash
uv run ruff check iam_validator/checks/{check_name}.py
uv run ruff format iam_validator/checks/{check_name}.py
uv run pytest tests/checks/test_{check_name}_check.py -v
```

### 8. Update Defaults

- Update `iam_validator/core/config/defaults.py` with new check's default config
- Update `examples/configs/full-reference-config.yaml`

### 9. Update Documentation

- **CHANGELOG.md**: Add entry under `### Added`
- **Root CLAUDE.md**: Add to "Built-in Checks" table
- **`iam_validator/checks/CLAUDE.md`**: Add to "File Reference" table

## Reference Checks by Type

**Statement-Level**: `wildcard_action.py`, `wildcard_resource.py`, `action_validation.py`, `condition_key_validation.py`

**Policy-Level**: `sid_uniqueness.py`, `policy_size.py`, `policy_structure.py`, `policy_type_validation.py`

**Combined**: `action_condition_enforcement.py`, `sensitive_action.py`

## Examples

- `/add-check require_vpc_restriction` — statement-level
- `/add-check duplicate_permission_detection` — policy-level
- `/add-check tag_enforcement` — will ask for type
