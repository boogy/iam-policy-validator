---
title: SDK API
description: SDK function reference
---

# SDK API Reference

High-level functions for IAM policy validation, AWS service queries, ARN utilities, and custom check development.

## Installation

```bash
pip install iam-policy-validator
# or
uv add iam-policy-validator
```

---

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

Validate an IAM policy from a Python dictionary or JSON string.

```python
async def validate_json(
    policy_json: dict | str,
    policy_name: str = "inline-policy",
    config_path: str | None = None,
) -> PolicyValidationResult
```

**Parameters:**

| Name          | Type          | Description                                |
| ------------- | ------------- | ------------------------------------------ |
| `policy_json` | `dict \| str` | IAM policy as a Python dict or JSON string |
| `policy_name` | `str`         | Name to identify this policy in results    |
| `config_path` | `str \| None` | Optional path to configuration file        |

**Returns:** `PolicyValidationResult`

**Raises:**

- `json.JSONDecodeError` — If a string is provided that is not valid JSON
- `TypeError` — If `policy_json` is not a `dict` or `str`

**Example:**

```python
from iam_validator.sdk import validate_json

# From a dict
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

# From a JSON string
result = await validate_json('{"Version": "2012-10-17", "Statement": [...]}')
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

### filter_issues_by_check_id

Filter validation issues from a result by check ID.

```python
def filter_issues_by_check_id(
    result: PolicyValidationResult,
    check_id: str,
) -> list[ValidationIssue]
```

**Parameters:**

| Name       | Type                     | Description                                                             |
| ---------- | ------------------------ | ----------------------------------------------------------------------- |
| `result`   | `PolicyValidationResult` | Validation result to filter                                             |
| `check_id` | `str`                    | Check ID to filter by (e.g., `"wildcard_action"`, `"sensitive_action"`) |

**Returns:** `list[ValidationIssue]` — Issues matching the check ID

**Example:**

```python
from iam_validator.sdk import validate_file, filter_issues_by_check_id

result = await validate_file("policy.json")
wildcard_issues = filter_issues_by_check_id(result, "wildcard_action")
print(f"Found {len(wildcard_issues)} wildcard action issues")
```

---

### filter_issues_by_severity

Filter validation issues from a result by minimum severity threshold.

```python
def filter_issues_by_severity(
    result: PolicyValidationResult,
    min_severity: str = "medium",
) -> list[ValidationIssue]
```

**Parameters:**

| Name           | Type                     | Description                                                                                     |
| -------------- | ------------------------ | ----------------------------------------------------------------------------------------------- |
| `result`       | `PolicyValidationResult` | Validation result to filter                                                                     |
| `min_severity` | `str`                    | Minimum severity: `"error"`, `"critical"`, `"high"`, `"warning"`, `"medium"`, `"low"`, `"info"` |

**Returns:** `list[ValidationIssue]` — Issues at or above the severity threshold

**Example:**

```python
from iam_validator.sdk import validate_file, filter_issues_by_severity

result = await validate_file("policy.json")
high_issues = filter_issues_by_severity(result, "high")
print(f"Found {len(high_issues)} high+ severity issues")
```

---

## Context Manager

### validator

Context manager for validation with shared resources. Creates an `AWSServiceFetcher` that is shared across all validations within the block, improving performance for batch operations.

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

### validator_from_config

Context manager that loads configuration from a file.

```python
@asynccontextmanager
async def validator_from_config(
    config_path: str,
) -> AsyncIterator[ValidationContext]
```

**Example:**

```python
from iam_validator.sdk import validator_from_config

async with validator_from_config("./iam-validator.yaml") as v:
    results = await v.validate_directory("./policies")
    v.generate_report(results)
```

### ValidationContext

The context object provides these methods:

| Method                                    | Description                          |
| ----------------------------------------- | ------------------------------------ |
| `validate_file(path)`                     | Validate a single policy file        |
| `validate_directory(path)`                | Validate all policies in a directory |
| `validate_json(policy_json, policy_name)` | Validate a policy dict               |
| `generate_report(results, format)`        | Generate a formatted report          |

Supported report formats: `"console"`, `"json"`, `"html"`, `"csv"`, `"markdown"`, `"sarif"`

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

### extract_condition_keys

Extract all condition keys from all statements in a policy.

```python
def extract_condition_keys(policy: IAMPolicy) -> set[str]
```

**Example:**

```python
from iam_validator.sdk import parse_policy, extract_condition_keys

policy = parse_policy(policy_json)
keys = extract_condition_keys(policy)
# {'aws:ResourceAccount', 'aws:ResourceTag/Environment'}
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

Query actions for a service with optional filtering.

```python
async def query_actions(
    fetcher: AWSServiceFetcher,
    service: str,
    access_level: AccessLevel | None = None,
    resource_type: str | None = None,
    condition: str | None = None,
) -> list[ActionInfo]
```

**Parameters:**

| Name            | Type                  | Description                                                                    |
| --------------- | --------------------- | ------------------------------------------------------------------------------ |
| `fetcher`       | `AWSServiceFetcher`   | AWS service fetcher instance                                                   |
| `service`       | `str`                 | Service name (e.g., `"s3"`, `"ec2"`)                                           |
| `access_level`  | `AccessLevel \| None` | Filter: `"read"`, `"write"`, `"list"`, `"tagging"`, `"permissions-management"` |
| `resource_type` | `str \| None`         | Filter by resource type. Use `"*"` for wildcard-only actions                   |
| `condition`     | `str \| None`         | Filter by condition key support                                                |

**Returns:** `list[ActionInfo]` — List of dicts with `action`, `access_level`, and `description` keys.

**Example:**

```python
from iam_validator.sdk import AWSServiceFetcher, query_actions

async with AWSServiceFetcher() as fetcher:
    # Get all S3 actions
    all_actions = await query_actions(fetcher, "s3")

    # Get only write actions
    write_actions = await query_actions(fetcher, "s3", access_level="write")
    print(f"S3 write actions: {len(write_actions)}")

    # Get wildcard-only actions
    wildcard_actions = await query_actions(fetcher, "iam", resource_type="*")

    # Get actions supporting a condition key
    mfa_actions = await query_actions(
        fetcher, "iam", condition="aws:MultiFactorAuthPresent"
    )
```

---

### query_action_details

Get detailed information about a specific action.

```python
async def query_action_details(
    fetcher: AWSServiceFetcher,
    service: str,
    action_name: str,
) -> ActionDetails
```

**Parameters:**

| Name          | Type                | Description                                       |
| ------------- | ------------------- | ------------------------------------------------- |
| `fetcher`     | `AWSServiceFetcher` | AWS service fetcher instance                      |
| `service`     | `str`               | Service name (e.g., `"s3"`, `"iam"`)              |
| `action_name` | `str`               | Action name (e.g., `"GetObject"`, `"CreateUser"`) |

**Returns:** `ActionDetails` — Dict with `service`, `action`, `description`, `access_level`, `resource_types`, and `condition_keys`.

**Raises:** `ValueError` — If action is not found

**Example:**

```python
from iam_validator.sdk import AWSServiceFetcher, query_action_details

async with AWSServiceFetcher() as fetcher:
    details = await query_action_details(fetcher, "s3", "GetObject")
    print(f"Access level: {details['access_level']}")
    print(f"Resource types: {details['resource_types']}")
    print(f"Condition keys: {details['condition_keys']}")
```

---

### query_arn_formats

Get ARN formats for a service.

```python
async def query_arn_formats(
    fetcher: AWSServiceFetcher,
    service: str,
) -> list[str]
```

**Returns:** `list[str]` — List of unique ARN format strings

**Example:**

```python
from iam_validator.sdk import AWSServiceFetcher, query_arn_formats

async with AWSServiceFetcher() as fetcher:
    arns = await query_arn_formats(fetcher, "s3")
    for arn in arns:
        print(arn)
```

---

### query_arn_types

Get all ARN resource types with their formats for a service.

```python
async def query_arn_types(
    fetcher: AWSServiceFetcher,
    service: str,
) -> list[ArnTypeInfo]
```

**Returns:** `list[ArnTypeInfo]` — List of dicts with `resource_type` and `arn_formats` keys.

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
) -> ArnFormatDetails
```

**Parameters:**

| Name                 | Type                | Description                           |
| -------------------- | ------------------- | ------------------------------------- |
| `fetcher`            | `AWSServiceFetcher` | AWS service fetcher instance          |
| `service`            | `str`               | Service name (e.g., `"s3"`, `"iam"`)  |
| `resource_type_name` | `str`               | Resource type name (e.g., `"bucket"`) |

**Returns:** `ArnFormatDetails` — Dict with `service`, `resource_type`, `arn_formats`, and `condition_keys`.

**Raises:** `ValueError` — If resource type is not found

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
) -> list[ConditionKeyInfo]
```

**Returns:** `list[ConditionKeyInfo]` — List of dicts with `condition_key`, `description`, and `types` keys.

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
) -> ConditionKeyDetails
```

**Returns:** `ConditionKeyDetails` — Dict with `service`, `condition_key`, `description`, and `types`.

**Raises:** `ValueError` — If condition key is not found

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
    access_level: AccessLevel,
) -> list[str]
```

**Parameters:**

| Name           | Type                | Description                                                                          |
| -------------- | ------------------- | ------------------------------------------------------------------------------------ |
| `fetcher`      | `AWSServiceFetcher` | AWS service fetcher instance                                                         |
| `service`      | `str`               | Service name                                                                         |
| `access_level` | `AccessLevel`       | Access level: `"read"`, `"write"`, `"list"`, `"tagging"`, `"permissions-management"` |

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

## TypedDicts

The query functions return typed dictionaries for better IDE support and type safety.

### ActionInfo

Returned by `query_actions()`.

```python
class ActionInfo(TypedDict):
    action: str         # Full action name (e.g., "s3:GetObject")
    access_level: str   # "read", "write", "list", "tagging", "permissions-management"
    description: str    # Human-readable description
```

### ActionDetails

Returned by `query_action_details()`.

```python
class ActionDetails(TypedDict):
    service: str             # Service prefix (e.g., "s3")
    action: str              # Action name (e.g., "GetObject")
    description: str         # Human-readable description
    access_level: str        # Access level
    resource_types: list[str]  # Supported resource types
    condition_keys: list[str]  # Supported condition keys
```

### ConditionKeyInfo

Returned by `query_condition_keys()`.

```python
class ConditionKeyInfo(TypedDict):
    condition_key: str   # Full key name (e.g., "s3:prefix")
    description: str     # Human-readable description
    types: list[str]     # Value types (e.g., ["String"])
```

### ConditionKeyDetails

Returned by `query_condition_key()`.

```python
class ConditionKeyDetails(TypedDict):
    service: str         # Service prefix
    condition_key: str   # Full key name
    description: str     # Human-readable description
    types: list[str]     # Value types
```

### ArnTypeInfo

Returned by `query_arn_types()`.

```python
class ArnTypeInfo(TypedDict):
    resource_type: str       # Resource type name (e.g., "bucket")
    arn_formats: list[str]   # ARN format strings
```

### ArnFormatDetails

Returned by `query_arn_format()`.

```python
class ArnFormatDetails(TypedDict):
    service: str             # Service prefix
    resource_type: str       # Resource type name
    arn_formats: list[str]   # ARN format strings
    condition_keys: list[str]  # Associated condition keys
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

| Name            | Type          | Description                                 |
| --------------- | ------------- | ------------------------------------------- |
| `arn_pattern`   | `str`         | ARN pattern (can have wildcards)            |
| `arn`           | `str`         | ARN from policy (can have wildcards)        |
| `resource_type` | `str \| None` | Optional resource type for special handling |

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

### normalize_template_variables

Normalize template variables in ARN to valid placeholders for validation. Handles Terraform, CloudFormation, and AWS policy variables.

```python
def normalize_template_variables(arn: str) -> str
```

This function is position-aware — it replaces variables with appropriate values based on their position in the ARN structure (e.g., account IDs for position 4, regions for position 3).

**Supported variable formats:**

- Terraform/Terragrunt: `${var.name}`, `${local.value}`, `${data.source.attr}`
- CloudFormation: `${AWS::AccountId}`, `${AWS::Region}`, `${MyParameter}`
- AWS policy variables: `${aws:username}`, `${aws:PrincipalTag/tag-key}`

**Example:**

```python
from iam_validator.sdk import normalize_template_variables

normalize_template_variables("arn:aws:iam::${my_account}:role/name")
# 'arn:aws:iam::123456789012:role/name'

normalize_template_variables("arn:aws:iam::${AWS::AccountId}:role/name")
# 'arn:aws:iam::123456789012:role/name'

normalize_template_variables("arn:${var.partition}:s3:::${var.bucket}/*")
# 'arn:aws:s3:::placeholder/*'
```

---

### has_template_variables

Check if an ARN contains template variables.

```python
def has_template_variables(arn: str) -> bool
```

**Example:**

```python
from iam_validator.sdk import has_template_variables

has_template_variables("arn:aws:iam::${aws_account_id}:role/name")  # True
has_template_variables("arn:aws:iam::123456789012:role/name")       # False
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

If no fetcher is provided, a temporary one is created and properly cleaned up after use.

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

## Exceptions

The SDK defines a hierarchy of exceptions for error handling:

| Exception                    | Parent              | When Raised                         |
| ---------------------------- | ------------------- | ----------------------------------- |
| `IAMValidatorError`          | `Exception`         | Base for all SDK errors             |
| `PolicyLoadError`            | `IAMValidatorError` | Failed to load or parse policy file |
| `InvalidPolicyFormatError`   | `PolicyLoadError`   | Invalid JSON/YAML or missing fields |
| `UnsupportedPolicyTypeError` | `PolicyLoadError`   | Unrecognized policy type            |
| `PolicyValidationError`      | `IAMValidatorError` | Validation failed critically        |
| `ConfigurationError`         | `IAMValidatorError` | Invalid or missing configuration    |
| `AWSServiceError`            | `IAMValidatorError` | AWS service data unavailable        |

**Example:**

```python
from iam_validator.sdk import (
    validate_file,
    PolicyLoadError,
    AWSServiceError,
    IAMValidatorError,
)

try:
    result = await validate_file("policy.json")
except PolicyLoadError:
    print("Could not load policy file")
except AWSServiceError:
    print("Could not fetch AWS service data")
except IAMValidatorError as e:
    print(f"Validation error: {e}")
```

---

## Models

### IAMPolicy

Pydantic model representing an IAM policy document.

```python
from iam_validator.sdk import IAMPolicy
```

Key fields: `version`, `statement` (list of `Statement`), `id` (optional).

### Statement

Pydantic model representing a single IAM policy statement.

```python
from iam_validator.sdk import Statement
```

Key fields: `sid`, `effect`, `action`, `resource`, `condition`, `principal`.

### ValidationIssue

Pydantic model representing a single validation finding.

```python
from iam_validator.sdk import ValidationIssue
```

Key fields: `severity`, `message`, `issue_type`, `check_id`, `suggestion`, `action`, `resource`, `condition_key`.

### PolicyValidationResult

Pydantic model representing validation results for a single policy.

```python
from iam_validator.sdk import PolicyValidationResult
```

Key fields: `policy_file`, `is_valid`, `issues` (list of `ValidationIssue`).

---

## Formatters

| Formatter           | Import                                            | Output Format           |
| ------------------- | ------------------------------------------------- | ----------------------- |
| `JSONFormatter`     | `from iam_validator.sdk import JSONFormatter`     | JSON                    |
| `HTMLFormatter`     | `from iam_validator.sdk import HTMLFormatter`     | HTML report             |
| `CSVFormatter`      | `from iam_validator.sdk import CSVFormatter`      | CSV                     |
| `MarkdownFormatter` | `from iam_validator.sdk import MarkdownFormatter` | Markdown (for PRs)      |
| `SARIFFormatter`    | `from iam_validator.sdk import SARIFFormatter`    | SARIF (static analysis) |

---

## Best Practices

### Context Managers vs Shortcuts

Use **shortcut functions** (`validate_file`, `validate_json`, etc.) for one-off validations. Use the **context manager** (`validator()`) when validating multiple policies to share the `AWSServiceFetcher` across calls:

```python
# One-off: shortcut is simpler
result = await validate_file("policy.json")

# Batch: context manager avoids creating a new fetcher each time
async with validator() as v:
    for path in policy_files:
        result = await v.validate_file(path)
```

### Batch Processing for Performance

When validating many policies, use `validate_directory()` or the context manager to share resources. The `AWSServiceFetcher` caches service definitions in memory, so reusing it avoids repeated HTTP requests:

```python
from iam_validator.sdk import validator
from pathlib import Path

async with validator() as v:
    policy_files = list(Path("./policies").glob("**/*.json"))
    results = []

    for i, policy_file in enumerate(policy_files):
        result = await v.validate_file(str(policy_file))
        results.append(result)

    # Generate a combined report
    report = v.generate_report(results, format="json")
```

### Caching Behavior

The `AWSServiceFetcher` uses a multi-layer caching strategy:

- **Memory LRU cache** — Service definitions are cached in memory during the session
- **Disk TTL cache** — Fetched data is stored on disk with a 7-day TTL (platform-specific paths)

For offline environments, pre-download service definitions:

```bash
iam-validator download-services
```

### Async Patterns

All validation functions are async. Use `asyncio.run()` in synchronous entry points:

```python
import asyncio
from iam_validator.sdk import validate_file

# In a script
result = asyncio.run(validate_file("policy.json"))

# In an existing async context
async def my_handler():
    result = await validate_file("policy.json")
    return result.is_valid
```

### Filtering Results

Use the filtering functions to drill down into specific issue types after validation:

```python
from iam_validator.sdk import (
    validate_file,
    filter_issues_by_check_id,
    filter_issues_by_severity,
)

result = await validate_file("policy.json")

# Find all wildcard-related issues
wildcard_issues = filter_issues_by_check_id(result, "wildcard_action")

# Find only critical and high severity issues
critical_issues = filter_issues_by_severity(result, "critical")
high_plus_issues = filter_issues_by_severity(result, "high")
```

---

## Integration Patterns

### Combining Validation with Policy Analysis

```python
import asyncio
from iam_validator.sdk import (
    validate_file,
    parse_policy,
    get_policy_summary,
    extract_actions,
    has_public_access,
    is_resource_policy,
    filter_issues_by_severity,
)


async def audit_policy(path: str):
    # Step 1: Validate
    result = await validate_file(path)

    # Step 2: Analyze structure
    with open(path) as f:
        policy = parse_policy(f.read())

    summary = get_policy_summary(policy)
    actions = extract_actions(policy)

    # Step 3: Build audit report
    report = {
        "file": path,
        "is_valid": result.is_valid,
        "total_issues": len(result.issues),
        "critical_issues": len(filter_issues_by_severity(result, "critical")),
        "is_resource_policy": is_resource_policy(policy),
        "has_public_access": has_public_access(policy),
        "services_used": summary["services"],
        "action_count": summary["action_count"],
        "has_wildcards": summary["has_wildcards"],
    }
    return report


report = asyncio.run(audit_policy("policy.json"))
```

### Building Custom Checks Using SDK Helpers

```python
from typing import ClassVar

from iam_validator.core.check_registry import CheckConfig, PolicyCheck
from iam_validator.core.models import Statement, ValidationIssue
from iam_validator.sdk import CheckHelper, AWSServiceFetcher


class NoS3DeleteCheck(PolicyCheck):
    """Prevent s3:Delete* actions on production buckets."""

    check_id: ClassVar[str] = "no_s3_delete"
    description: ClassVar[str] = "Blocks S3 delete actions on production buckets"
    default_severity: ClassVar[str] = "high"

    async def execute(
        self,
        statement: Statement,
        statement_idx: int,
        fetcher: AWSServiceFetcher,
        config: CheckConfig,
    ) -> list[ValidationIssue]:
        helper = CheckHelper(fetcher)
        issues = []

        # Expand wildcards like "s3:Delete*" to concrete actions
        actions = statement.get_actions()
        expanded = await helper.expand_actions(actions)

        delete_actions = [a for a in expanded if "Delete" in a and a.startswith("s3:")]
        if not delete_actions:
            return []

        # Check if any resource targets production buckets
        for resource in statement.get_resources():
            if helper.arn_matches("arn:*:s3:::prod-*", resource):
                issues.append(
                    helper.create_issue(
                        severity="high",
                        statement_idx=statement_idx,
                        message=f"S3 delete actions on production bucket: {', '.join(delete_actions)}",
                        resource=resource,
                        suggestion="Remove delete permissions or use a Deny statement instead",
                    )
                )

        return issues
```

### Processing Multiple Policies Efficiently

```python
import asyncio
from pathlib import Path

from iam_validator.sdk import (
    validator,
    filter_issues_by_severity,
    JSONFormatter,
    ReportGenerator,
)


async def batch_validate(directory: str):
    async with validator() as v:
        # Validate all policies in one pass
        results = await v.validate_directory(directory)

        # Separate clean vs problematic policies
        clean = [r for r in results if r.is_valid]
        problematic = [r for r in results if not r.is_valid]

        print(f"Clean: {len(clean)}/{len(results)}")
        print(f"Problematic: {len(problematic)}/{len(results)}")

        # Drill into problematic policies
        for result in problematic:
            critical = filter_issues_by_severity(result, "critical")
            if critical:
                print(f"  CRITICAL in {result.policy_file}:")
                for issue in critical:
                    print(f"    - {issue.message}")

        # Export JSON report
        generator = ReportGenerator()
        report = generator.generate_report(results)
        json_output = JSONFormatter().format(report)

        Path("validation-report.json").write_text(json_output)
        print("Report saved to validation-report.json")


asyncio.run(batch_validate("./policies"))
```

### Querying AWS Service Data

```python
from iam_validator.sdk import (
    AWSServiceFetcher,
    query_actions,
    query_action_details,
    query_condition_keys,
    get_actions_by_access_level,
    get_wildcard_only_actions,
)


async def explore_service(service: str):
    async with AWSServiceFetcher() as fetcher:
        # Overview
        all_actions = await query_actions(fetcher, service)
        print(f"{service} has {len(all_actions)} actions")

        # Breakdown by access level
        for level in ["read", "write", "list", "tagging", "permissions-management"]:
            actions = await get_actions_by_access_level(fetcher, service, level)
            print(f"  {level}: {len(actions)} actions")

        # Find dangerous actions (wildcard-only, no resource restriction)
        wildcard_only = await get_wildcard_only_actions(fetcher, service)
        print(f"  Wildcard-only: {len(wildcard_only)} actions")

        # Get details for a specific action
        if all_actions:
            action_name = all_actions[0]["action"].split(":")[1]
            details = await query_action_details(fetcher, service, action_name)
            print(f"\n  Example: {details['action']}")
            print(f"    Access level: {details['access_level']}")
            print(f"    Resource types: {details['resource_types']}")

        # List condition keys
        keys = await query_condition_keys(fetcher, service)
        print(f"\n  {len(keys)} condition keys available")
```

---

## Troubleshooting

### "No IAM policies found" Error

The `PolicyLoader` looks for files with `.json` or `.yaml`/`.yml` extensions that contain IAM policy structure (a `Statement` field). If your files aren't being detected:

- Verify the file extension is `.json`, `.yaml`, or `.yml`
- Ensure the policy has a `Statement` key at the top level
- Check that the file path or directory exists

```python
from iam_validator.sdk import validate_file

try:
    result = await validate_file("policy.json")
except ValueError as e:
    print(f"Error: {e}")
    # "No IAM policies found in policy.json"
```

### AWS Service Data Fetch Failures

If the SDK can't fetch AWS service definitions (e.g., no internet access), pre-download them:

```bash
# Download all service definitions for offline use
iam-validator download-services
```

Or catch the error programmatically:

```python
from iam_validator.sdk import validate_file, AWSServiceError

try:
    result = await validate_file("policy.json")
except AWSServiceError:
    print("Cannot reach AWS service API. Run 'iam-validator download-services' for offline use.")
```

### validate_json Accepts Both dict and str

`validate_json()` accepts both Python dictionaries and JSON strings:

```python
from iam_validator.sdk import validate_json

# Both work:
result = await validate_json({"Version": "2012-10-17", "Statement": [...]})
result = await validate_json('{"Version": "2012-10-17", "Statement": [...]}')
```

If you pass a string that isn't valid JSON, a `json.JSONDecodeError` is raised.

### Running Async Functions from Synchronous Code

All SDK validation functions are async. Use `asyncio.run()` to call them from synchronous code:

```python
import asyncio
from iam_validator.sdk import validate_file

# Correct
result = asyncio.run(validate_file("policy.json"))

# Inside an existing event loop (e.g., Jupyter notebooks)
result = await validate_file("policy.json")
```

### Resource Cleanup with expand_actions

The `expand_actions()` function properly manages its own `AWSServiceFetcher` when called without one. For multiple calls, pass a shared fetcher to avoid creating temporary resources:

```python
from iam_validator.sdk import expand_actions, AWSServiceFetcher

# Single call — fine, creates and cleans up its own fetcher
actions = await expand_actions(["s3:Get*"])

# Multiple calls — pass a shared fetcher
async with AWSServiceFetcher() as fetcher:
    s3_actions = await expand_actions(["s3:Get*"], fetcher)
    iam_actions = await expand_actions(["iam:Create*"], fetcher)
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
    filter_issues_by_severity,
    filter_issues_by_check_id,
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

    # Filter a result by check ID
    wildcard_issues = filter_issues_by_check_id(result, "wildcard_action")
    print(f"Wildcard issues: {len(wildcard_issues)}")

    # Filter a result by severity
    critical_issues = filter_issues_by_severity(result, "critical")
    print(f"Critical issues: {len(critical_issues)}")

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
