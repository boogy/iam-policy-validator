---
title: Advanced Usage
description: Advanced SDK patterns and context managers
---

# Advanced Usage

Advanced patterns for efficient SDK usage.

## Context Managers

### validator()

Use `validator()` for efficient batch validation:

```python
from iam_validator.sdk import validator

async with validator() as v:
    # AWS fetcher is created once and reused
    r1 = await v.validate_file("policy1.json")
    r2 = await v.validate_file("policy2.json")
    r3 = await v.validate_directory("./policies/")

    # Generate reports
    v.generate_report([r1, r2, r3], format="console")
    json_report = v.generate_report([r1, r2, r3], format="json")
```

### With Configuration

```python
async with validator(config_path="./iam-validator.yaml") as v:
    results = await v.validate_directory("./policies/")
```

## Report Generation

Generate reports in various formats:

```python
from iam_validator.sdk import validate_directory, ReportGenerator

results = await validate_directory("./policies/")

generator = ReportGenerator()
report = generator.generate_report(results)

# Console
generator.print_console_report(report)

# JSON
from iam_validator.sdk import JSONFormatter
json_output = JSONFormatter().format(report)

# HTML
from iam_validator.sdk import HTMLFormatter
html_output = HTMLFormatter().format(report)

# CSV
from iam_validator.sdk import CSVFormatter
csv_output = CSVFormatter().format(report)
```

## Check Registry

Register custom checks programmatically:

```python
from iam_validator.sdk import CheckRegistry, PolicyCheck

class MyCheck(PolicyCheck):
    check_id = "my_check"
    description = "My custom check"
    default_severity = "high"

    async def execute(self, statement, idx, fetcher, config):
        issues = []
        # Check logic here
        return issues

# Register
CheckRegistry.register_check(MyCheck)

# Now runs with validations
result = await validate_file("policy.json")
```

## AWS Service Fetcher

Access AWS service definitions:

```python
from iam_validator.sdk import AWSServiceFetcher

async with AWSServiceFetcher() as fetcher:
    # Validate an action
    is_valid, error, is_wildcard = await fetcher.validate_action("s3:GetObject")

    # Expand wildcards
    actions = await fetcher.expand_wildcard_action("s3:Get*")

    # Get service definition
    s3 = await fetcher.fetch_service_by_name("s3")
```

## Query Functions

Query AWS service definitions:

```python
from iam_validator.sdk import (
    query_actions,
    query_arn_formats,
    query_condition_keys,
    get_actions_by_access_level,
)

async with AWSServiceFetcher() as fetcher:
    # Get all S3 write actions
    write_actions = await query_actions(fetcher, "s3", access_level="write")

    # Get ARN formats
    arns = await query_arn_formats(fetcher, "s3")

    # Get condition keys
    conditions = await query_condition_keys(fetcher, "s3")

    # Get high-privilege actions
    high_priv = await get_actions_by_access_level(
        fetcher, "iam", "permissions-management"
    )
```

## Error Handling

```python
from iam_validator.sdk import (
    validate_file,
    PolicyLoadError,
    PolicyValidationError,
    ConfigurationError,
)

try:
    result = await validate_file("policy.json")
except PolicyLoadError as e:
    print(f"Failed to load policy: {e}")
except ConfigurationError as e:
    print(f"Invalid configuration: {e}")
except PolicyValidationError as e:
    print(f"Validation error: {e}")
```

## Async Patterns

### Concurrent Validation

```python
import asyncio
from iam_validator.sdk import validate_file

async def validate_many(files):
    tasks = [validate_file(f) for f in files]
    results = await asyncio.gather(*tasks)
    return results

files = ["policy1.json", "policy2.json", "policy3.json"]
results = asyncio.run(validate_many(files))
```

### With Semaphore (Rate Limiting)

```python
import asyncio
from iam_validator.sdk import validate_file

async def validate_with_limit(files, max_concurrent=5):
    semaphore = asyncio.Semaphore(max_concurrent)

    async def limited_validate(file):
        async with semaphore:
            return await validate_file(file)

    tasks = [limited_validate(f) for f in files]
    return await asyncio.gather(*tasks)
```
