---
title: Architecture
description: System architecture and design
---

# Architecture

Overview of IAM Policy Validator's architecture and design.

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────┐
│                      CLI / SDK                          │
├─────────────────────────────────────────────────────────┤
│                   Policy Loader                         │
│              (JSON/YAML → IAMPolicy)                    │
├─────────────────────────────────────────────────────────┤
│                 Validation Engine                       │
│         (CheckRegistry → Parallel Execution)            │
├───────────────────────┬─────────────────────────────────┤
│   Built-in Checks     │     Custom Checks               │
│   (19 checks)         │     (User-defined)              │
├───────────────────────┴─────────────────────────────────┤
│              AWS Service Fetcher                        │
│         (Service definitions, caching)                  │
├─────────────────────────────────────────────────────────┤
│                Report Generator                         │
│         (Console, JSON, SARIF, HTML, etc.)              │
└─────────────────────────────────────────────────────────┘
```

## Components

### Policy Loader

Loads and parses IAM policies from various sources:

- JSON files
- YAML files
- Directories (recursive)
- Python dicts

```python
from iam_validator.core.policy_loader import PolicyLoader

loader = PolicyLoader()
policies = loader.load_from_path("./policies/")
```

### Check Registry

Manages validation checks and orchestrates execution:

```python
from iam_validator.core.check_registry import CheckRegistry

registry = CheckRegistry()
registry.register_check(MyCheck)

# Execute all checks in parallel
issues = await registry.execute_checks_parallel(
    statement, idx, fetcher, config
)
```

### AWS Service Fetcher

Fetches and caches AWS service definitions:

- HTTP/2 connection pooling
- Memory LRU cache
- Disk cache with TTL (7 days)
- Offline support

```python
from iam_validator.core.aws_service import AWSServiceFetcher

async with AWSServiceFetcher() as fetcher:
    service = await fetcher.fetch_service_by_name("s3")
    is_valid, error, _ = await fetcher.validate_action("s3:GetObject")
```

### Report Generator

Generates reports in various formats:

```python
from iam_validator.core.report import ReportGenerator

generator = ReportGenerator()
report = generator.generate_report(results)
output = generator.format_report(report, format="json")
```

## Data Models

### IAMPolicy

```python
class IAMPolicy(BaseModel):
    version: str
    id: str | None = None
    statement: list[Statement]
```

### Statement

```python
class Statement(BaseModel):
    sid: str | None = None
    effect: str  # "Allow" or "Deny"
    action: str | list[str] | None = None
    not_action: str | list[str] | None = None
    resource: str | list[str] | None = None
    not_resource: str | list[str] | None = None
    principal: dict | str | None = None
    condition: dict | None = None
    line_number: int | None = None
```

### ValidationIssue

```python
class ValidationIssue(BaseModel):
    severity: str
    statement_index: int
    issue_type: str
    message: str
    check_id: str | None = None
    statement_sid: str | None = None
    action: str | None = None
    resource: str | None = None
    condition_key: str | None = None
    suggestion: str | None = None
    example: str | None = None
    line_number: int | None = None
```

## Processing Pipeline

```
PolicyLoader.load_from_file()
    ↓
validate_policies() in policy_checks.py
    ↓
CheckRegistry.execute_policy_checks() [policy-level]
    ↓
CheckRegistry.execute_checks_parallel() [statement-level, async]
    ↓
ReportGenerator.generate_report()
    ↓
Formatter output (console|json|sarif|html|csv|markdown)
```

## Configuration System

Configuration is loaded with priority:

1. CLI arguments (highest)
2. Config file (`iam-validator.yaml`)
3. Python defaults (lowest)

```python
from iam_validator.core.config import ConfigLoader

config = ConfigLoader.load("./iam-validator.yaml")
```

## Caching Strategy

### Memory Cache

- LRU cache for frequently accessed services
- Clears on process exit

### Disk Cache

- Platform-specific cache directory
- 7-day TTL by default
- Can be cleared with `iam-validator cache clear`

### Cache Locations

| Platform | Location                              |
| -------- | ------------------------------------- |
| Linux    | `~/.cache/iam-validator/`             |
| macOS    | `~/Library/Caches/iam-validator/`     |
| Windows  | `%LOCALAPPDATA%\iam-validator\Cache\` |
