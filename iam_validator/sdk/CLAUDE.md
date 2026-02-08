# SDK Module - Python Library Usage Guide

**Purpose**: Public API for using IAM Policy Validator as a Python library
**Parent Context**: Extends [../../CLAUDE.md](../../CLAUDE.md)

---

## Quick Start

### Basic Validation

```python
from iam_validator.sdk import validate_file, validate_json, validate_directory

# Validate a single file
result = await validate_file("policy.json")
print(f"Valid: {result.is_valid}, Issues: {len(result.issues)}")

# Validate JSON string
policy_json = '{"Version": "2012-10-17", "Statement": [...]}'
result = await validate_json(policy_json)

# Validate entire directory
results = await validate_directory("./policies/", recursive=True)
for result in results:
    print(f"{result.policy_file}: {len(result.issues)} issues")
```

### Using Context Manager

```python
from iam_validator.sdk import validator

async with validator() as v:
    # Validate multiple files with shared fetcher
    result1 = await v.validate_file("policy1.json")
    result2 = await v.validate_file("policy2.json")

    # Generate report
    v.generate_report([result1, result2], format="markdown")
```

### With Configuration

```python
from iam_validator.sdk import validator_from_config, load_validator_config

# Load from YAML file
config = load_validator_config("iam-validator.yaml")

async with validator_from_config(config) as v:
    result = await v.validate_file("policy.json")
```

---

## Module Exports

### High-Level Shortcuts (`shortcuts.py`)

| Function                              | Purpose                            |
| ------------------------------------- | ---------------------------------- |
| `validate_file(path)`                 | Validate single policy file        |
| `validate_directory(path, recursive)` | Validate all policies in directory |
| `validate_json(json_str)`             | Validate JSON string               |
| `quick_validate(policy_dict)`         | Quick validation of dict           |
| `get_issues(result)`                  | Extract issues from result         |
| `count_issues_by_severity(result)`    | Count issues by severity           |

### Context Managers (`context.py`)

| Function                        | Purpose                    |
| ------------------------------- | -------------------------- |
| `validator()`                   | Create validation context  |
| `validator_from_config(config)` | Context with custom config |
| `ValidationContext`             | Class for custom contexts  |

### Policy Utilities (`policy_utils.py`)

| Function                                          | Purpose                     |
| ------------------------------------------------- | --------------------------- |
| `parse_policy(json_str)`                          | Parse JSON to IAMPolicy     |
| `normalize_policy(policy)`                        | Normalize policy structure  |
| `extract_actions(policy)`                         | Get all actions from policy |
| `extract_resources(policy)`                       | Get all resources           |
| `extract_condition_keys(policy)`                  | Get all condition keys      |
| `find_statements_with_action(policy, action)`     | Find statements by action   |
| `find_statements_with_resource(policy, resource)` | Find by resource            |
| `merge_policies(policies)`                        | Merge multiple policies     |
| `get_policy_summary(policy)`                      | Get policy statistics       |
| `policy_to_json(policy)`                          | Convert to JSON string      |
| `policy_to_dict(policy)`                          | Convert to dict             |
| `is_resource_policy(policy)`                      | Check if resource policy    |
| `has_public_access(policy)`                       | Check for public access     |

### Query Utilities (`query_utils.py`)

| Function                                                  | Purpose                |
| --------------------------------------------------------- | ---------------------- |
| `query_actions(fetcher, service)`                         | List service actions   |
| `query_action_details(fetcher, action)`                   | Get action metadata    |
| `query_arn_formats(fetcher, service)`                     | Get ARN formats        |
| `query_arn_types(fetcher, service)`                       | Get resource types     |
| `query_condition_keys(fetcher, service)`                  | Get condition keys     |
| `query_condition_key(fetcher, service, key)`              | Get condition details  |
| `get_actions_by_access_level(fetcher, service, level)`    | Filter by access level |
| `get_wildcard_only_actions(fetcher, service)`             | Actions requiring `*`  |
| `get_actions_supporting_condition(fetcher, service, key)` | Filter by condition    |

### ARN Utilities (`arn_matching.py`)

| Function                                   | Purpose                 |
| ------------------------------------------ | ----------------------- |
| `arn_matches(pattern, arn)`                | Glob-style ARN matching |
| `arn_strictly_valid(pattern, arn)`         | Strict validation       |
| `is_glob_match(pattern, value)`            | Generic glob match      |
| `convert_aws_pattern_to_wildcard(pattern)` | Convert AWS patterns    |

### Core Components

| Export                | Purpose                  |
| --------------------- | ------------------------ |
| `PolicyCheck`         | Base class for checks    |
| `CheckRegistry`       | Check management         |
| `AWSServiceFetcher`   | AWS service data         |
| `PolicyLoader`        | Load policies            |
| `ReportGenerator`     | Generate reports         |
| `validate_policies()` | Core validation function |

### Models

| Model                    | Purpose                   |
| ------------------------ | ------------------------- |
| `IAMPolicy`              | Policy with statements    |
| `Statement`              | Single policy statement   |
| `ValidationIssue`        | Single validation finding |
| `PolicyValidationResult` | Result for one policy     |

### Formatters

| Formatter           | Output             |
| ------------------- | ------------------ |
| `JSONFormatter`     | JSON output        |
| `HTMLFormatter`     | HTML report        |
| `CSVFormatter`      | CSV output         |
| `MarkdownFormatter` | Markdown (for PRs) |
| `SARIFFormatter`    | SARIF format       |

### Exceptions

| Exception                    | When Raised           |
| ---------------------------- | --------------------- |
| `IAMValidatorError`          | Base exception        |
| `PolicyLoadError`            | Failed to load policy |
| `PolicyValidationError`      | Validation failed     |
| `ConfigurationError`         | Invalid config        |
| `AWSServiceError`            | AWS API error         |
| `InvalidPolicyFormatError`   | Bad policy format     |
| `UnsupportedPolicyTypeError` | Unknown policy type   |

---

## Common Patterns

### Batch Validation with Progress

```python
from iam_validator.sdk import validator
from pathlib import Path

async def validate_all_policies(directory: str):
    async with validator() as v:
        policy_files = list(Path(directory).glob("**/*.json"))
        results = []

        for i, policy_file in enumerate(policy_files):
            print(f"Validating {i+1}/{len(policy_files)}: {policy_file}")
            result = await v.validate_file(str(policy_file))
            results.append(result)

        total_issues = sum(len(r.issues) for r in results)
        print(f"Total: {len(results)} policies, {total_issues} issues")
        return results
```

### Custom Validation Pipeline

```python
from iam_validator.sdk import (
    AWSServiceFetcher,
    CheckRegistry,
    PolicyLoader,
    validate_policies,
)

async def custom_validation():
    registry = CheckRegistry()
    registry.register(MyCustomCheck())

    async with AWSServiceFetcher() as fetcher:
        loader = PolicyLoader()
        policies = await loader.load_from_directory("./policies/")

        results = await validate_policies(
            policies=policies,
            fetcher=fetcher,
            registry=registry,
        )
        return results
```

### Query AWS Service Data

```python
from iam_validator.sdk import (
    AWSServiceFetcher,
    query_actions,
    get_actions_by_access_level,
)

async def explore_service(service_name: str):
    async with AWSServiceFetcher() as fetcher:
        # List all actions
        actions = await query_actions(fetcher, service_name)
        print(f"{service_name} has {len(actions)} actions")

        # Get write actions only
        write_actions = await get_actions_by_access_level(
            fetcher, service_name, "write"
        )
        print(f"Write actions: {len(write_actions)}")
```

### Generate Reports

```python
from iam_validator.sdk import (
    validator,
    JSONFormatter,
    MarkdownFormatter,
)

async def generate_reports():
    async with validator() as v:
        results = await v.validate_directory("./policies/")

        # JSON report
        json_formatter = JSONFormatter()
        with open("report.json", "w") as f:
            f.write(json_formatter.format(results))

        # Markdown report (for GitHub PRs)
        md_formatter = MarkdownFormatter()
        print(md_formatter.format(results))
```

---

## File Reference

| File              | Purpose                         |
| ----------------- | ------------------------------- |
| `__init__.py`     | Public API exports              |
| `shortcuts.py`    | High-level validation functions |
| `context.py`      | Context managers                |
| `policy_utils.py` | Policy manipulation             |
| `query_utils.py`  | AWS service queries             |
| `arn_matching.py` | ARN pattern matching            |
| `helpers.py`      | Check development helpers       |
| `exceptions.py`   | Public exceptions               |

---

## Quick Search

```bash
# Find exported function
rg -n "^def |^async def " .

# Find where function is defined
rg -n "def validate_file" .

# Find all exports
rg -n "__all__" .

# Find usage in examples
rg -n "from iam_validator.sdk" ../../examples/
```
