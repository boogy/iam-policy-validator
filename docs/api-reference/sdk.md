---
title: SDK API
description: SDK function reference
---

# SDK API Reference

High-level functions for IAM policy validation.

## Validation Functions

### validate_file

Validate a single IAM policy file.

```python
async def validate_file(
    file_path: str | Path,
    config_path: str | None = None,
    config: ValidatorConfig | None = None,
) -> PolicyValidationResult
```

**Parameters:**

| Name | Type | Description |
|------|------|-------------|
| `file_path` | `str \| Path` | Path to the policy file (JSON or YAML) |
| `config_path` | `str \| None` | Optional path to configuration file |
| `config` | `ValidatorConfig \| None` | Optional config object (overrides config_path) |

**Returns:** `PolicyValidationResult`

**Example:**

```python
from iam_validator.sdk import validate_file

result = await validate_file("policy.json")
if result.is_valid:
    print("Policy is valid!")
else:
    for issue in result.issues:
        print(f"{issue.severity}: {issue.message}")
```

---

### validate_directory

Validate all IAM policies in a directory.

```python
async def validate_directory(
    dir_path: str | Path,
    config_path: str | None = None,
    config: ValidatorConfig | None = None,
    recursive: bool = True,
) -> list[PolicyValidationResult]
```

**Parameters:**

| Name | Type | Description |
|------|------|-------------|
| `dir_path` | `str \| Path` | Path to directory containing policy files |
| `config_path` | `str \| None` | Optional path to configuration file |
| `config` | `ValidatorConfig \| None` | Optional config object |
| `recursive` | `bool` | Search subdirectories (default: `True`) |

**Returns:** `list[PolicyValidationResult]`

**Example:**

```python
from iam_validator.sdk import validate_directory

results = await validate_directory("./policies")
valid_count = sum(1 for r in results if r.is_valid)
print(f"{valid_count}/{len(results)} policies are valid")
```

---

### validate_json

Validate an IAM policy from a Python dictionary.

```python
async def validate_json(
    policy_json: dict,
    policy_name: str = "inline-policy",
    config_path: str | None = None,
    config: ValidatorConfig | None = None,
) -> PolicyValidationResult
```

**Parameters:**

| Name | Type | Description |
|------|------|-------------|
| `policy_json` | `dict` | IAM policy as a Python dict |
| `policy_name` | `str` | Name to identify this policy in results |
| `config_path` | `str \| None` | Optional path to configuration file |
| `config` | `ValidatorConfig \| None` | Optional config object |

**Returns:** `PolicyValidationResult`

**Example:**

```python
from iam_validator.sdk import validate_json

policy = {
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::my-bucket/*"
    }]
}
result = await validate_json(policy)
print(f"Valid: {result.is_valid}")
```

---

### quick_validate

Quick validation returning just `True`/`False`. Automatically detects input type.

```python
async def quick_validate(
    policy: str | Path | dict,
    config_path: str | None = None,
    config: ValidatorConfig | None = None,
) -> bool
```

**Parameters:**

| Name | Type | Description |
|------|------|-------------|
| `policy` | `str \| Path \| dict` | File path, directory path, or policy dict |
| `config_path` | `str \| None` | Optional path to configuration file |
| `config` | `ValidatorConfig \| None` | Optional config object |

**Returns:** `bool` — `True` if all policies are valid

**Example:**

```python
from iam_validator.sdk import quick_validate

# Validate a file
if await quick_validate("policy.json"):
    print("Policy is valid!")

# Validate a directory
if await quick_validate("./policies"):
    print("All policies are valid!")

# Validate a dict
policy = {"Version": "2012-10-17", "Statement": [...]}
if await quick_validate(policy):
    print("Policy is valid!")
```

---

### get_issues

Get validation issues filtered by severity.

```python
async def get_issues(
    policy: str | Path | dict,
    min_severity: str = "medium",
    config_path: str | None = None,
    config: ValidatorConfig | None = None,
) -> list[ValidationIssue]
```

**Parameters:**

| Name | Type | Description |
|------|------|-------------|
| `policy` | `str \| Path \| dict` | File path, directory path, or policy dict |
| `min_severity` | `str` | Minimum severity: `critical`, `high`, `medium`, `low`, `info` |
| `config_path` | `str \| None` | Optional path to configuration file |
| `config` | `ValidatorConfig \| None` | Optional config object |

**Returns:** `list[ValidationIssue]`

**Example:**

```python
from iam_validator.sdk import get_issues

# Get only high and critical issues
issues = await get_issues("policy.json", min_severity="high")
for issue in issues:
    print(f"{issue.severity}: {issue.message}")
```

---

### count_issues_by_severity

Count issues grouped by severity level.

```python
async def count_issues_by_severity(
    policy: str | Path | dict,
    config_path: str | None = None,
    config: ValidatorConfig | None = None,
) -> dict[str, int]
```

**Returns:** `dict[str, int]` — Mapping of severity to count

**Example:**

```python
from iam_validator.sdk import count_issues_by_severity

counts = await count_issues_by_severity("./policies")
print(f"Critical: {counts.get('critical', 0)}")
print(f"High: {counts.get('high', 0)}")
print(f"Medium: {counts.get('medium', 0)}")
```

---

## Context Manager

### validator

Context manager for validation with shared resources.

```python
@asynccontextmanager
async def validator(
    config_path: str | None = None,
) -> AsyncIterator[ValidationContext]
```

**Example:**

```python
from iam_validator.sdk import validator

async with validator() as v:
    # Validate multiple files with shared AWS fetcher
    result1 = await v.validate_file("policy1.json")
    result2 = await v.validate_file("policy2.json")

    # Generate a report
    v.generate_report([result1, result2])
```

### ValidationContext

The context object provides these methods:

| Method | Description |
|--------|-------------|
| `validate_file(path)` | Validate a single policy file |
| `validate_directory(path)` | Validate all policies in a directory |
| `generate_report(results)` | Print a formatted report |

---

## Policy Utilities

### parse_policy

Parse a policy from JSON string or dict.

```python
def parse_policy(policy: str | dict) -> IAMPolicy
```

**Example:**

```python
from iam_validator.sdk import parse_policy

policy = parse_policy('{"Version": "2012-10-17", "Statement": [...]}')
print(f"Statements: {len(policy.statement)}")
```

---

### extract_actions

Extract all actions from a policy.

```python
def extract_actions(policy: IAMPolicy) -> list[str]
```

**Example:**

```python
from iam_validator.sdk import parse_policy, extract_actions

policy = parse_policy(policy_json)
actions = extract_actions(policy)
print(f"Actions used: {actions}")
# ['s3:GetObject', 's3:PutObject', 'ec2:DescribeInstances']
```

---

### extract_resources

Extract all resources from a policy.

```python
def extract_resources(policy: IAMPolicy) -> list[str]
```

**Example:**

```python
from iam_validator.sdk import parse_policy, extract_resources

policy = parse_policy(policy_json)
resources = extract_resources(policy)
print(f"Resources: {resources}")
# ['arn:aws:s3:::my-bucket/*', 'arn:aws:ec2:*:*:instance/*']
```

---

### get_policy_summary

Get a summary of policy contents.

```python
def get_policy_summary(policy: IAMPolicy) -> dict[str, Any]
```

**Returns:**

```python
{
    "statement_count": 3,
    "action_count": 5,
    "resource_count": 2,
    "has_wildcards": True,
    "effects": ["Allow", "Deny"],
    "services": ["s3", "ec2", "iam"],
}
```

**Example:**

```python
from iam_validator.sdk import parse_policy, get_policy_summary

policy = parse_policy(policy_json)
summary = get_policy_summary(policy)
print(f"Actions: {summary['action_count']}")
print(f"Services: {summary['services']}")
```

---

## AWS Service Queries

### AWSServiceFetcher

Fetcher for AWS service definitions with caching.

```python
from iam_validator.sdk import AWSServiceFetcher

async with AWSServiceFetcher() as fetcher:
    # Validate an action exists
    is_valid, error, is_wildcard = await fetcher.validate_action("s3:GetObject")

    # Expand wildcard action
    actions = await fetcher.expand_wildcard_action("s3:Get*")

    # Fetch service definition
    s3_service = await fetcher.fetch_service_by_name("s3")
```

---

### query_actions

Query actions for a service, optionally filtered by access level.

```python
async def query_actions(
    fetcher: AWSServiceFetcher,
    service: str,
    access_level: str | None = None,
) -> list[str]
```

**Parameters:**

| Name | Type | Description |
|------|------|-------------|
| `fetcher` | `AWSServiceFetcher` | AWS service fetcher instance |
| `service` | `str` | Service name (e.g., `s3`, `ec2`) |
| `access_level` | `str \| None` | Filter: `read`, `write`, `list`, `tagging`, `permissions-management` |

**Example:**

```python
from iam_validator.sdk import AWSServiceFetcher, query_actions

async with AWSServiceFetcher() as fetcher:
    # Get all S3 actions
    all_actions = await query_actions(fetcher, "s3")

    # Get only write actions
    write_actions = await query_actions(fetcher, "s3", access_level="write")
    print(f"S3 write actions: {len(write_actions)}")
```

---

### query_arn_formats

Get ARN formats for a service.

```python
async def query_arn_formats(
    fetcher: AWSServiceFetcher,
    service: str,
) -> list[dict]
```

**Example:**

```python
from iam_validator.sdk import AWSServiceFetcher, query_arn_formats

async with AWSServiceFetcher() as fetcher:
    arns = await query_arn_formats(fetcher, "s3")
    for arn in arns:
        print(f"{arn['resource_type']}: {arn['arn']}")
```

---

## Complete Example

```python
import asyncio
from iam_validator.sdk import (
    validate_file,
    get_issues,
    parse_policy,
    get_policy_summary,
    validator,
)


async def main():
    # Simple validation
    result = await validate_file("policy.json")
    print(f"Valid: {result.is_valid}")

    # Get high-severity issues only
    issues = await get_issues("policy.json", min_severity="high")
    for issue in issues:
        print(f"[{issue.severity}] {issue.message}")
        if issue.suggestion:
            print(f"  → {issue.suggestion}")

    # Analyze policy structure
    with open("policy.json") as f:
        policy = parse_policy(f.read())

    summary = get_policy_summary(policy)
    print(f"Services used: {summary['services']}")
    print(f"Has wildcards: {summary['has_wildcards']}")

    # Batch validation with context manager
    async with validator() as v:
        results = await v.validate_directory("./policies")
        v.generate_report(results)


if __name__ == "__main__":
    asyncio.run(main())
```
