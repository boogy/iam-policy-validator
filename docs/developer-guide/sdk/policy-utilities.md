---
title: Policy Utilities
description: Parse, analyze, and manipulate IAM policies
---

# Policy Utilities

Utilities for parsing, analyzing, and manipulating IAM policies.

## Parsing

### parse_policy

Parse a policy from JSON string or dict.

```python
from iam_validator.sdk import parse_policy

# From JSON string
policy_str = '{"Version": "2012-10-17", "Statement": [...]}'
policy = parse_policy(policy_str)

# From dict
policy_dict = {"Version": "2012-10-17", "Statement": [...]}
policy = parse_policy(policy_dict)
```

## Extraction

### extract_actions

Get all actions from a policy.

```python
from iam_validator.sdk import extract_actions

actions = extract_actions(policy)
# ['s3:GetObject', 's3:PutObject', 'iam:PassRole']
```

### extract_resources

Get all resources from a policy.

```python
from iam_validator.sdk import extract_resources

resources = extract_resources(policy)
# ['arn:aws:s3:::bucket/*', 'arn:aws:iam::123456789012:role/*']
```

### extract_condition_keys

Get all condition keys used in a policy.

```python
from iam_validator.sdk import extract_condition_keys

keys = extract_condition_keys(policy)
# ['aws:SourceAccount', 's3:prefix']
```

### extract_condition_keys_from_statement

Get all condition keys from a single statement.

```python
from iam_validator.sdk import extract_condition_keys_from_statement

# Extract keys from a specific statement
keys = extract_condition_keys_from_statement(statement)
# {'aws:ResourceAccount', 'aws:ResourceTag/Environment'}
```

This is useful when you need to analyze conditions at the statement level rather than the entire policy.

## Analysis

### get_policy_summary

Get statistics about a policy.

```python
from iam_validator.sdk import get_policy_summary

summary = get_policy_summary(policy)

print(f"Statements: {summary['statement_count']}")
print(f"Actions: {summary['action_count']}")
print(f"Resources: {summary['resource_count']}")
print(f"Allow statements: {summary['allow_statements']}")
print(f"Deny statements: {summary['deny_statements']}")
print(f"Has wildcards: {summary['has_wildcard_actions']}")
```

### is_resource_policy

Check if a policy is a resource policy (has Principal).

```python
from iam_validator.sdk import is_resource_policy

if is_resource_policy(policy):
    print("This is a resource policy")
```

### has_public_access

Check if a policy allows public access.

```python
from iam_validator.sdk import has_public_access

if has_public_access(policy):
    print("WARNING: Policy allows public access!")
```

## Searching

### find_statements_with_action

Find statements containing a specific action.

```python
from iam_validator.sdk import find_statements_with_action

statements = find_statements_with_action(policy, "s3:GetObject")

for stmt in statements:
    print(f"Statement {stmt.sid}: {stmt.effect}")
```

### find_statements_with_resource

Find statements with a specific resource.

```python
from iam_validator.sdk import find_statements_with_resource

statements = find_statements_with_resource(
    policy,
    "arn:aws:s3:::my-bucket/*"
)
```

## Manipulation

### merge_policies

Merge multiple policies into one.

```python
from iam_validator.sdk import merge_policies

merged = merge_policies(policy1, policy2)
print(f"Merged has {len(merged.statement)} statements")
```

## Conversion

### policy_to_json

Convert a policy object to JSON string.

```python
from iam_validator.sdk import policy_to_json

json_str = policy_to_json(policy, indent=2)
```

### policy_to_dict

Convert a policy object to a Python dict.

```python
from iam_validator.sdk import policy_to_dict

policy_dict = policy_to_dict(policy)
```

## ARN Utilities

### arn_matches

Check if an ARN matches a pattern with wildcards.

```python
from iam_validator.sdk import arn_matches

if arn_matches("arn:*:s3:::*/*", resource):
    print("Matches S3 object pattern")
```
