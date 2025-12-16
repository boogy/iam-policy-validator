---
title: Python SDK
description: Use IAM Policy Validator as a Python library
---

# Python SDK

The IAM Policy Validator SDK provides programmatic access to all validation features.

## Installation

```bash
pip install iam-policy-validator
```

## Quick Start

```python
import asyncio
from iam_validator.sdk import validate_file, quick_validate

async def main():
    # Simple True/False validation
    is_valid = await quick_validate("policy.json")
    print(f"Valid: {is_valid}")

    # Detailed validation with issues
    result = await validate_file("policy.json")
    if not result.is_valid:
        for issue in result.issues:
            print(f"{issue.severity}: {issue.message}")

asyncio.run(main())
```

## Topics

- [Quick Start](quickstart.md) — Get started quickly
- [Validation](validation.md) — Validation functions
- [Policy Utilities](policy-utilities.md) — Parse, analyze, and manipulate policies
- [Advanced Usage](advanced.md) — Context managers and advanced patterns
