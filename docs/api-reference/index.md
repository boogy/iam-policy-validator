---
title: API Reference
description: Complete API documentation
---

# API Reference

Complete API documentation for IAM Policy Validator.

## Modules

- [SDK](sdk.md) — High-level SDK functions
- [Models](models.md) — Data models
- [Checks](checks.md) — Check base classes
- [Exceptions](exceptions.md) — Exception classes

## Quick Import Guide

```python
# High-level validation
from iam_validator.sdk import (
    validate_file,
    validate_directory,
    validate_json,
    quick_validate,
    validator,
)

# Models
from iam_validator.sdk import (
    IAMPolicy,
    Statement,
    ValidationIssue,
    PolicyValidationResult,
    Config,
)

# Custom checks
from iam_validator.core.check_registry import PolicyCheck, CheckConfig
from iam_validator.core.aws_service import AWSServiceFetcher

# Exceptions
from iam_validator.sdk import (
    IAMValidatorError,
    PolicyLoadError,
    PolicyValidationError,
    ConfigurationError,
)
```
