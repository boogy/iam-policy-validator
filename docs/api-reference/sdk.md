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
) -> PolicyValidationResult
```

**Parameters:**

| Name          | Type          | Description                            |
| ------------- | ------------- | -------------------------------------- |
| `file_path`   | `str \| Path` | Path to the policy file (JSON or YAML) |
| `config_path` | `str \| None` | Optional path to configuration file    |

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
    recursive: bool = True,
) -> list[PolicyValidationResult]
```

**Parameters:**

| Name          | Type          | Description                               |
| ------------- | ------------- | ----------------------------------------- |
| `dir_path`    | `str \| Path` | Path to directory containing policy files |
| `config_path` | `str \| None` | Optional path to configuration file       |
| `recursive`   | `bool`        | Search subdirectories (default: `True`)   |

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
) -> PolicyValidationResult
```

**Parameters:**

| Name          | Type          | Description                             |
| ------------- | ------------- | --------------------------------------- |
| `policy_json` | `dict`        | IAM policy as a Python dict             |
| `policy_name` | `str`         | Name to identify this policy in results |
| `config_path` | `str \| None` | Optional path to configuration file     |

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
) -> bool
```

**Parameters:**

| Name          | Type                  | Description                               |
| ------------- | --------------------- | ----------------------------------------- |
| `policy`      | `str \| Path \| dict` | File path, directory path, or policy dict |
| `config_path` | `str \| None`         | Optional path to configuration file       |

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
) -> list[ValidationIssue]
```

**Parameters:**

| Name           | Type                  | Description                                                   |
| -------------- | --------------------- | ------------------------------------------------------------- |
| `policy`       | `str \| Path \| dict` | File path, directory path, or policy dict                     |
| `min_severity` | `str`                 | Minimum severity: `critical`, `high`, `medium`, `low`, `info` |
| `config_path`  | `str \| None`         | Optional path to configuration file                           |

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

| Method                     | Description                          |
| -------------------------- | ------------------------------------ |
| `validate_file(path)`      | Validate a single policy file        |
| `validate_directory(path)` | Validate all policies in a directory |
| `generate_report(results)` | Print a formatted report             |

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

### extract_condition_keys_from_statement

Extract all condition keys from a single statement.

```python
def extract_condition_keys_from_statement(statement: Statement) -> set[str]
```

**Parameters:**

| Name        | Type        | Description                                  |
| ----------- | ----------- | -------------------------------------------- |
| `statement` | `Statement` | The statement to extract condition keys from |

**Returns:** `set[str]` — Set of condition key names

**Example:**

```python
from iam_validator.sdk import extract_condition_keys_from_statement
from iam_validator.core.models import Statement

statement = Statement(
    Effect="Allow",
    Action=["s3:GetObject"],
    Resource=["*"],
    Condition={
        "StringEquals": {
            "aws:ResourceAccount": "123456789012",
            "aws:ResourceTag/Environment": "production"
        }
    }
)

keys = extract_condition_keys_from_statement(statement)
# {'aws:ResourceAccount', 'aws:ResourceTag/Environment'}
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

| Name           | Type                | Description                                                          |
| -------------- | ------------------- | -------------------------------------------------------------------- |
| `fetcher`      | `AWSServiceFetcher` | AWS service fetcher instance                                         |
| `service`      | `str`               | Service name (e.g., `s3`, `ec2`)                                     |
| `access_level` | `str \| None`       | Filter: `read`, `write`, `list`, `tagging`, `permissions-management` |

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

### query_arn_types

Get all ARN resource types with their formats for a service.

```python
async def query_arn_types(
    fetcher: AWSServiceFetcher,
    service: str,
) -> list[dict[str, Any]]
```

**Returns:** List of dictionaries with `resource_type` and `arn_formats` keys.

**Example:**

```python
from iam_validator.sdk import AWSServiceFetcher, query_arn_types

async with AWSServiceFetcher() as fetcher:
    types = await query_arn_types(fetcher, "s3")
    for rt in types:
        print(f"{rt['resource_type']}: {rt['arn_formats']}")
```

---

### query_arn_format

Get ARN format details for a specific resource type.

```python
async def query_arn_format(
    fetcher: AWSServiceFetcher,
    service: str,
    resource_type_name: str,
) -> dict[str, Any]
```

**Parameters:**

| Name                 | Type                | Description                           |
| -------------------- | ------------------- | ------------------------------------- |
| `fetcher`            | `AWSServiceFetcher` | AWS service fetcher instance          |
| `service`            | `str`               | Service name (e.g., `s3`, `iam`)      |
| `resource_type_name` | `str`               | Resource type name (e.g., `bucket`)   |

**Example:**

```python
from iam_validator.sdk import AWSServiceFetcher, query_arn_format

async with AWSServiceFetcher() as fetcher:
    details = await query_arn_format(fetcher, "s3", "bucket")
    print(f"ARN formats: {details['arn_formats']}")
    print(f"Condition keys: {details['condition_keys']}")
```

---

### query_condition_keys

Query all condition keys for a service.

```python
async def query_condition_keys(
    fetcher: AWSServiceFetcher,
    service: str,
) -> list[dict[str, Any]]
```

**Returns:** List of dictionaries with `condition_key`, `description`, and `types` keys.

**Example:**

```python
from iam_validator.sdk import AWSServiceFetcher, query_condition_keys

async with AWSServiceFetcher() as fetcher:
    keys = await query_condition_keys(fetcher, "s3")
    for key in keys:
        print(f"{key['condition_key']}: {key['description']}")
```

---

### query_condition_key

Get details for a specific condition key.

```python
async def query_condition_key(
    fetcher: AWSServiceFetcher,
    service: str,
    condition_key_name: str,
) -> dict[str, Any]
```

**Example:**

```python
from iam_validator.sdk import AWSServiceFetcher, query_condition_key

async with AWSServiceFetcher() as fetcher:
    details = await query_condition_key(fetcher, "s3", "s3:prefix")
    print(f"Types: {details['types']}")
    print(f"Description: {details['description']}")
```

---

### get_actions_by_access_level

Get action names filtered by access level.

```python
async def get_actions_by_access_level(
    fetcher: AWSServiceFetcher,
    service: str,
    access_level: str,
) -> list[str]
```

**Parameters:**

| Name           | Type                | Description                                                          |
| -------------- | ------------------- | -------------------------------------------------------------------- |
| `fetcher`      | `AWSServiceFetcher` | AWS service fetcher instance                                         |
| `service`      | `str`               | Service name                                                         |
| `access_level` | `str`               | Access level: `read`, `write`, `list`, `tagging`, `permissions-management` |

**Example:**

```python
from iam_validator.sdk import AWSServiceFetcher, get_actions_by_access_level

async with AWSServiceFetcher() as fetcher:
    write_actions = await get_actions_by_access_level(fetcher, "s3", "write")
    print(f"Found {len(write_actions)} write actions")
```

---

### get_wildcard_only_actions

Get actions that only support wildcard resources (no specific resource types).

```python
async def get_wildcard_only_actions(
    fetcher: AWSServiceFetcher,
    service: str,
) -> list[str]
```

**Example:**

```python
from iam_validator.sdk import AWSServiceFetcher, get_wildcard_only_actions

async with AWSServiceFetcher() as fetcher:
    wildcard_actions = await get_wildcard_only_actions(fetcher, "iam")
    print(f"IAM has {len(wildcard_actions)} wildcard-only actions")
```

---

### get_actions_supporting_condition

Get actions that support a specific condition key.

```python
async def get_actions_supporting_condition(
    fetcher: AWSServiceFetcher,
    service: str,
    condition_key: str,
) -> list[str]
```

**Example:**

```python
from iam_validator.sdk import AWSServiceFetcher, get_actions_supporting_condition

async with AWSServiceFetcher() as fetcher:
    mfa_actions = await get_actions_supporting_condition(
        fetcher, "iam", "aws:MultiFactorAuthPresent"
    )
    print(f"Actions supporting MFA condition: {len(mfa_actions)}")
```

---

## ARN Utilities

Functions for matching and validating AWS ARN patterns.

### arn_matches

Check if an ARN matches a pattern with glob support.

```python
def arn_matches(
    arn_pattern: str,
    arn: str,
    resource_type: str | None = None,
) -> bool
```

**Parameters:**

| Name            | Type          | Description                                      |
| --------------- | ------------- | ------------------------------------------------ |
| `arn_pattern`   | `str`         | ARN pattern (can have wildcards)                 |
| `arn`           | `str`         | ARN from policy (can have wildcards)             |
| `resource_type` | `str \| None` | Optional resource type for special handling      |

**Example:**

```python
from iam_validator.sdk import arn_matches

# Basic matching
arn_matches("arn:*:s3:::*/*", "arn:aws:s3:::bucket/key")  # True
arn_matches("arn:*:s3:::*/*", "arn:aws:s3:::bucket")      # False

# Both can have wildcards
arn_matches("arn:*:s3:::*/*", "arn:aws:s3:::*personalize*")  # True

# S3 bucket validation (no "/" allowed)
arn_matches("arn:*:s3:::*", "arn:aws:s3:::bucket/key", resource_type="bucket")  # False
```

---

### arn_strictly_valid

Strictly validate ARN against pattern with resource type checking.

```python
def arn_strictly_valid(
    arn_pattern: str,
    arn: str,
    resource_type: str | None = None,
) -> bool
```

This is stricter than `arn_matches()` and enforces that the resource type portion matches exactly.

**Example:**

```python
from iam_validator.sdk import arn_strictly_valid

# Valid: has resource type "user"
arn_strictly_valid(
    "arn:*:iam::*:user/*",
    "arn:aws:iam::123456789012:user/alice"
)  # True

# Invalid: missing resource type
arn_strictly_valid(
    "arn:*:iam::*:user/*",
    "arn:aws:iam::123456789012:u*"
)  # False
```

---

### is_glob_match

Recursive glob pattern matching for two strings. Both strings can contain wildcards.

```python
def is_glob_match(s1: str, s2: str) -> bool
```

**Example:**

```python
from iam_validator.sdk import is_glob_match

is_glob_match("*/*", "*personalize*")  # True
is_glob_match("*/*", "mybucket")       # False
is_glob_match("test*", "test123")      # True
```

---

### convert_aws_pattern_to_wildcard

Convert AWS ARN pattern format to wildcard pattern for matching.

```python
def convert_aws_pattern_to_wildcard(pattern: str) -> str
```

AWS provides ARN patterns with placeholders like `${Partition}`, `${BucketName}`. This function converts them to wildcard patterns.

**Example:**

```python
from iam_validator.sdk import convert_aws_pattern_to_wildcard

convert_aws_pattern_to_wildcard(
    "arn:${Partition}:s3:::${BucketName}/${ObjectName}"
)
# Returns: "arn:*:s3:::*/*"

convert_aws_pattern_to_wildcard(
    "arn:${Partition}:iam::${Account}:user/${UserNameWithPath}"
)
# Returns: "arn:*:iam::*:user/*"
```

---

## Additional Policy Utilities

### find_statements_with_action

Find all statements containing a specific action. Supports exact match and wildcard patterns.

```python
def find_statements_with_action(
    policy: IAMPolicy,
    action: str,
) -> list[Statement]
```

**Example:**

```python
from iam_validator.sdk import parse_policy, find_statements_with_action

policy = parse_policy(policy_json)
stmts = find_statements_with_action(policy, "s3:GetObject")
for stmt in stmts:
    print(f"Statement {stmt.sid} allows s3:GetObject")
```

---

### find_statements_with_resource

Find all statements containing a specific resource. Supports exact match and wildcard patterns.

```python
def find_statements_with_resource(
    policy: IAMPolicy,
    resource: str,
) -> list[Statement]
```

**Example:**

```python
from iam_validator.sdk import parse_policy, find_statements_with_resource

policy = parse_policy(policy_json)
stmts = find_statements_with_resource(policy, "arn:aws:s3:::my-bucket/*")
print(f"Found {len(stmts)} statements with this resource")
```

---

### merge_policies

Merge multiple policies into one. Combines all statements from multiple policies.

```python
def merge_policies(*policies: IAMPolicy) -> IAMPolicy
```

**Example:**

```python
from iam_validator.sdk import parse_policy, merge_policies

policy1 = parse_policy(json1)
policy2 = parse_policy(json2)
merged = merge_policies(policy1, policy2)
print(f"Merged policy has {len(merged.statement)} statements")
```

---

### normalize_policy

Normalize policy format (ensure statements are in list format).

```python
def normalize_policy(policy: IAMPolicy) -> IAMPolicy
```

AWS allows Statement to be a single object or an array. This function ensures it's always an array for consistent processing.

**Example:**

```python
from iam_validator.sdk import parse_policy, normalize_policy

policy = parse_policy(policy_json)
normalized = normalize_policy(policy)
assert isinstance(normalized.statement, list)
```

---

### has_public_access

Check if policy grants public access (`Principal: "*"`).

```python
def has_public_access(policy: IAMPolicy) -> bool
```

**Example:**

```python
from iam_validator.sdk import parse_policy, has_public_access

policy = parse_policy(policy_json)
if has_public_access(policy):
    print("WARNING: This policy allows public access!")
```

---

### is_resource_policy

Check if policy appears to be a resource policy (vs identity policy).

```python
def is_resource_policy(policy: IAMPolicy) -> bool
```

Resource policies have a Principal field, identity policies don't.

**Example:**

```python
from iam_validator.sdk import parse_policy, is_resource_policy

policy = parse_policy(bucket_policy_json)
if is_resource_policy(policy):
    print("This is an S3 bucket policy or similar")
```

---

### policy_to_json

Convert IAMPolicy to formatted JSON string.

```python
def policy_to_json(policy: IAMPolicy, indent: int = 2) -> str
```

**Example:**

```python
from iam_validator.sdk import parse_policy, policy_to_json

policy = parse_policy(policy_dict)
json_str = policy_to_json(policy)
print(json_str)
```

---

### policy_to_dict

Convert IAMPolicy to Python dictionary.

```python
def policy_to_dict(policy: IAMPolicy) -> dict[str, Any]
```

**Example:**

```python
from iam_validator.sdk import parse_policy, policy_to_dict

policy = parse_policy(policy_json)
policy_dict = policy_to_dict(policy)
print(policy_dict["Version"])
```

---

## Custom Check Development

### CheckHelper

All-in-one helper class for custom check development.

```python
from iam_validator.sdk import CheckHelper, AWSServiceFetcher

class CheckHelper:
    def __init__(self, fetcher: AWSServiceFetcher): ...

    async def expand_actions(self, actions: list[str]) -> list[str]: ...
    def arn_matches(self, pattern: str, arn: str, resource_type: str | None = None) -> bool: ...
    def arn_strictly_valid(self, pattern: str, arn: str, resource_type: str | None = None) -> bool: ...
    def create_issue(
        self,
        severity: str,
        statement_idx: int,
        message: str,
        statement_sid: str | None = None,
        issue_type: str = "custom",
        action: str | None = None,
        resource: str | None = None,
        condition_key: str | None = None,
        suggestion: str | None = None,
        line_number: int | None = None,
    ) -> ValidationIssue: ...
```

**Example:**

```python
from iam_validator.sdk import CheckHelper, PolicyCheck, AWSServiceFetcher

class MyCheck(PolicyCheck):
    check_id = "my_check"
    description = "My custom check"
    default_severity = "medium"

    async def execute(self, statement, idx, fetcher, config):
        helper = CheckHelper(fetcher)

        # Expand wildcards to concrete actions
        actions = await helper.expand_actions(["s3:Get*"])

        # Check ARN patterns
        for resource in statement.get_resources():
            if helper.arn_matches("arn:*:s3:::secret-*", resource):
                return [helper.create_issue(
                    severity="high",
                    statement_idx=idx,
                    message="Sensitive bucket access detected",
                    suggestion="Restrict access to specific resources"
                )]
        return []
```

---

### expand_actions

Expand action wildcards to concrete actions. Standalone function.

```python
async def expand_actions(
    actions: list[str],
    fetcher: AWSServiceFetcher | None = None,
) -> list[str]
```

**Example:**

```python
from iam_validator.sdk import expand_actions

# Without fetcher (creates temporary one)
actions = await expand_actions(["s3:Get*"])
# Returns: ["s3:GetObject", "s3:GetObjectVersion", ...]

# With fetcher (better for multiple calls)
from iam_validator.sdk import AWSServiceFetcher

async with AWSServiceFetcher() as fetcher:
    actions = await expand_actions(["s3:Get*"], fetcher)
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
