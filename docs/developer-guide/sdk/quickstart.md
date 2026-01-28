---
title: SDK Quick Start
description: Get started with the Python SDK
---

# SDK Quick Start

Get up and running with the Python SDK in minutes.

## Installation

```bash
pip install iam-policy-validator
```

### Installation Options

Install with optional dependencies for additional features:

```bash
# With MCP server support (for AI assistant integration)
pip install iam-policy-validator[mcp]

# With development dependencies (pytest, mypy, ruff)
pip install iam-policy-validator[dev]

# With documentation dependencies (mkdocs)
pip install iam-policy-validator[docs]
```

Or with uv:

```bash
# Basic installation
uv add iam-policy-validator

# With MCP server support
uv add iam-policy-validator[mcp]

# Sync with extras in pyproject.toml
uv sync --extra mcp
uv sync --extra dev
```

## Basic Validation

### Validate a File

```python
import asyncio
from iam_validator.sdk import validate_file

async def main():
    result = await validate_file("policy.json")

    print(f"Valid: {result.is_valid}")
    print(f"Issues: {len(result.issues)}")

    for issue in result.issues:
        print(f"  [{issue.severity}] {issue.message}")

asyncio.run(main())
```

### Quick Validation

Just need True/False?

```python
from iam_validator.sdk import quick_validate

is_valid = await quick_validate("policy.json")
```

### Validate a Directory

```python
from iam_validator.sdk import validate_directory

results = await validate_directory("./policies/")

for result in results:
    status = "PASS" if result.is_valid else "FAIL"
    print(f"{result.file_path}: {status}")
```

### Validate a Dict

```python
from iam_validator.sdk import validate_json

policy = {
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Action": "s3:GetObject",
        "Resource": "arn:aws:s3:::bucket/*"
    }]
}

result = await validate_json(policy)
```

## Using Configuration

```python
from iam_validator.sdk import validate_file

# Use a config file
result = await validate_file(
    "policy.json",
    config_path="./iam-validator.yaml"
)
```

## Context Manager

For multiple validations, use a context manager for efficiency:

```python
from iam_validator.sdk import validator

async with validator() as v:
    # Shares AWS fetcher across validations
    r1 = await v.validate_file("policy1.json")
    r2 = await v.validate_file("policy2.json")

    # Generate reports
    v.generate_report([r1, r2], format="console")
```

## Next Steps

- [Validation Functions](validation.md) — All validation functions
- [Policy Utilities](policy-utilities.md) — Parse and analyze policies
- [Advanced Usage](advanced.md) — Context managers and patterns
