---
title: Exceptions API
description: Exception classes reference
---

# Exceptions API Reference

## Exception Hierarchy

```
IAMValidatorError (base)
├── PolicyLoadError
├── PolicyValidationError
├── ConfigurationError
├── AWSServiceError
├── InvalidPolicyFormatError
└── UnsupportedPolicyTypeError
```

## IAMValidatorError

Base exception for all IAM Validator errors.

```python
from iam_validator.sdk import IAMValidatorError

try:
    result = await validate_file("policy.json")
except IAMValidatorError as e:
    print(f"Validation failed: {e}")
```

## PolicyLoadError

Raised when a policy file cannot be loaded.

```python
from iam_validator.sdk import PolicyLoadError

try:
    result = await validate_file("nonexistent.json")
except PolicyLoadError as e:
    print(f"Failed to load: {e}")
```

**Common causes:**

- File not found
- Invalid JSON/YAML syntax
- Permission denied

## PolicyValidationError

Raised when validation encounters an error.

```python
from iam_validator.sdk import PolicyValidationError

try:
    result = await validate_file("policy.json")
except PolicyValidationError as e:
    print(f"Validation error: {e}")
```

## ConfigurationError

Raised when configuration is invalid.

```python
from iam_validator.sdk import ConfigurationError

try:
    result = await validate_file(
        "policy.json",
        config_path="invalid-config.yaml"
    )
except ConfigurationError as e:
    print(f"Config error: {e}")
```

**Common causes:**

- Invalid YAML syntax
- Unknown check ID
- Invalid severity level

## AWSServiceError

Raised when AWS service data cannot be fetched.

```python
from iam_validator.sdk import AWSServiceError

try:
    async with AWSServiceFetcher() as fetcher:
        service = await fetcher.fetch_service_by_name("nonexistent")
except AWSServiceError as e:
    print(f"AWS service error: {e}")
```

## InvalidPolicyFormatError

Raised when policy format is invalid.

```python
from iam_validator.sdk import InvalidPolicyFormatError

try:
    policy = parse_policy("not valid json")
except InvalidPolicyFormatError as e:
    print(f"Invalid format: {e}")
```

## UnsupportedPolicyTypeError

Raised when policy type is not supported.

```python
from iam_validator.sdk import UnsupportedPolicyTypeError

try:
    result = await validate_file(
        "policy.json",
        policy_type="UNKNOWN_TYPE"
    )
except UnsupportedPolicyTypeError as e:
    print(f"Unsupported type: {e}")
```

## Error Handling Pattern

```python
from iam_validator.sdk import (
    validate_file,
    PolicyLoadError,
    PolicyValidationError,
    ConfigurationError,
    IAMValidatorError,
)

async def safe_validate(path: str) -> bool:
    try:
        result = await validate_file(path)
        return result.is_valid

    except PolicyLoadError as e:
        print(f"Could not load policy: {e}")
        return False

    except ConfigurationError as e:
        print(f"Configuration error: {e}")
        return False

    except PolicyValidationError as e:
        print(f"Validation failed: {e}")
        return False

    except IAMValidatorError as e:
        print(f"Unexpected error: {e}")
        return False
```
