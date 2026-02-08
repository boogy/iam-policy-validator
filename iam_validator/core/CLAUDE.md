# Core Module - Validation Engine Architecture

**Purpose**: Core validation engine, models, and AWS integration
**Parent Context**: Extends [../../CLAUDE.md](../../CLAUDE.md)

---

## Module Overview

```
core/
├── cli.py                  # CLI entry point (argparse)
├── check_registry.py       # Check plugin system
├── models.py               # Pydantic data models
├── policy_loader.py        # JSON/YAML policy loading
├── policy_checks.py        # Validation orchestrator
├── report.py               # Report generation (ContextIssueInfo, IgnoredFindingInfo)
├── pr_commenter.py         # PR comment posting with diff-aware filtering
├── diff_parser.py          # Git diff parsing for PR filtering
├── finding_fingerprint.py  # Fingerprint-based comment deduplication
├── label_manager.py        # GitHub PR label management
├── access_analyzer.py      # AWS Access Analyzer integration
├── ignore_patterns.py      # Ignore pattern matching
├── constants.py            # Global constants
├── aws_service/            # AWS service data fetcher
│   ├── __init__.py        # Public facade (AWSServiceFetcher)
│   ├── fetcher.py         # Main orchestrator
│   ├── client.py          # HTTP client (httpx, HTTP/2)
│   ├── cache.py           # Multi-layer caching
│   ├── storage.py         # Disk I/O
│   ├── validators.py      # Action/ARN validation
│   ├── parsers.py         # Action/ARN parsing
│   └── patterns.py        # Compiled regex patterns
├── config/                 # Configuration system
│   ├── config_loader.py   # YAML config loading
│   ├── defaults.py        # Default values
│   ├── sensitive_actions.py # 490+ sensitive actions
│   ├── condition_requirements.py # Required conditions
│   └── aws_global_conditions.py # AWS condition keys
└── formatters/             # Output formatters
    ├── base.py            # Abstract base
    ├── console.py         # Rich console output
    ├── json.py            # JSON format
    ├── markdown.py        # Markdown (PR comments)
    ├── sarif.py           # SARIF format
    ├── csv.py             # CSV format
    └── html.py            # HTML report
```

---

## Key Components

### Check Registry (`check_registry.py`)

Plugin system for validation checks:

```python
from iam_validator.core.check_registry import (
    PolicyCheck,      # Base class for checks
    CheckConfig,      # Per-check configuration
    CheckRegistry,    # Registry for managing checks
    create_default_registry,  # Factory with built-in checks
)
```

**When adding a new check**: Register it in `create_default_registry()`.

### Data Models (`models.py`)

Pydantic v2 models with validation:

```python
from iam_validator.core.models import (
    IAMPolicy,              # Full policy
    Statement,              # Single statement
    ValidationIssue,        # Single finding
    PolicyValidationResult, # Result for one policy
)

# Statement helper methods
statement.get_actions()     # Returns list[str]
statement.get_resources()   # Returns list[str]
statement.get_principals()  # Returns list[str]

# Policy types
PolicyType = Literal[
    "IDENTITY_POLICY",
    "RESOURCE_POLICY",
    "TRUST_POLICY",
    "SERVICE_CONTROL_POLICY",
    "RESOURCE_CONTROL_POLICY",
]
```

### Policy Loader (`policy_loader.py`)

Handles JSON/YAML loading with auto-detection:

```python
from iam_validator.core.policy_loader import PolicyLoader

loader = PolicyLoader()

# Load single file
policy = await loader.load_from_file("policy.json")

# Load directory
policies = await loader.load_from_directory("./policies/", recursive=True)

# Load from stdin
policy = await loader.load_from_stdin()

# Auto-detect format (JSON/YAML)
# Supports embedded policies (CloudFormation, Terraform)
```

### Validation Orchestrator (`policy_checks.py`)

Coordinates check execution:

```python
from iam_validator.core.policy_checks import validate_policies

results = await validate_policies(
    policies=policies,          # List[IAMPolicy]
    fetcher=fetcher,           # AWSServiceFetcher
    registry=registry,         # CheckRegistry (optional)
    config=config,             # ValidatorConfig (optional)
    policy_type="IDENTITY_POLICY",
)
```

**Execution Flow**:

1. Policy-level checks (`execute_policy_checks`)
2. Per-statement checks (`execute_checks_parallel`)
3. Ignore pattern filtering
4. Result aggregation

### PR Commenting Pipeline (`pr_commenter.py`)

Handles posting validation results to GitHub PRs with diff-aware filtering:

```
ValidationReport
    ↓
PRCommenter._post_review_comments()
    ↓
Diff filtering (3 tiers):
  1. Changed lines → inline review comments
  2. Modified statement, unchanged line → off-diff pipeline
  3. Unchanged statement → off-diff pipeline
    ↓
Off-diff pipeline (_post_off_diff_comments):
  Try line-level comment → file-level comment → collect for summary
    ↓
ReportGenerator.generate_github_comment_parts(context_issues=...)
    ↓
Summary comment with collapsible "Additional Findings" table
```

**Key classes**:

- `ContextIssue` — tracks off-diff issues with file path, statement index, line number
- `ContextIssueInfo` (in `report.py`) — dataclass for rendering context issues in summary
- `FindingFingerprint` — content-based hash for comment deduplication and cleanup protection

**Protected fingerprints**: Off-diff comments posted individually are protected from deletion during the `update_or_create_review_comments` cleanup phase via the `protected_fingerprints` parameter.

---

## AWS Service Module (`aws_service/`)

### Public API (`__init__.py`)

```python
from iam_validator.core.aws_service import AWSServiceFetcher

async with AWSServiceFetcher() as fetcher:
    # Validate action exists
    is_valid, error, is_wildcard = await fetcher.validate_action("s3:GetObject")

    # Expand wildcards
    actions = await fetcher.expand_wildcard_action("s3:Get*")

    # Fetch service definition
    service = await fetcher.fetch_service_by_name("s3")

    # Validate condition key
    is_valid = await fetcher.validate_condition_key("s3", "s3:x-amz-acl")

# Offline mode
async with AWSServiceFetcher(aws_services_dir="./aws-services") as fetcher:
    ...
```

### Architecture (SOLID Principles)

| File            | Responsibility                                        |
| --------------- | ----------------------------------------------------- |
| `fetcher.py`    | Orchestrator - coordinates all components             |
| `client.py`     | HTTP client - retry logic, HTTP/2, request coalescing |
| `cache.py`      | Multi-layer caching - memory LRU + disk TTL           |
| `storage.py`    | Disk I/O - TTL-based cache persistence                |
| `validators.py` | Validation logic - action/ARN/condition validation    |
| `parsers.py`    | Parsing - action/ARN pattern matching                 |
| `patterns.py`   | Singleton - pre-compiled regex patterns               |

### Caching Strategy

```
Request → Memory Cache (LRU)
              ↓ miss
        Disk Cache (TTL)
              ↓ miss
        AWS API (HTTPS)
              ↓
        Store in both caches
```

- **Memory**: LRU cache, stores raw JSON + Pydantic models
- **Disk**: TTL-based (7 days), stores raw JSON only
- **Locations**: `~/Library/Caches` (macOS), `~/.cache` (Linux), `%LOCALAPPDATA%` (Windows)

---

## Configuration System (`config/`)

### Config Loader (`config_loader.py`)

```python
from iam_validator.core.config.config_loader import (
    ValidatorConfig,
    load_validator_config,
)

# Load from YAML
config = load_validator_config("iam-validator.yaml")

# Priority: CLI args > config file > defaults
```

### YAML Structure

```yaml
# iam-validator.yaml
checks:
  wildcard_action:
    enabled: true
    severity: error
    config:
      message: "Custom message"
      suggestion: "Custom suggestion"

  sensitive_action:
    enabled: true
    severity: high

ignore_patterns:
  - filepath: "test/.*"
  - action: ".*:(Get|List|Describe).*"
  - sid: "AllowReadOnly"

# Global settings
fail_on_warnings: false
recursive: true
policy_type: IDENTITY_POLICY
```

### Config Modules

| File                        | Purpose                       |
| --------------------------- | ----------------------------- |
| `defaults.py`               | Default configuration values  |
| `sensitive_actions.py`      | 490+ actions by risk category |
| `condition_requirements.py` | Action → required conditions  |
| `aws_global_conditions.py`  | All AWS condition keys        |
| `service_principals.py`     | AWS service principals        |
| `wildcards.py`              | Wildcard handling config      |

---

## Formatters (`formatters/`)

### Adding a New Formatter

```python
from iam_validator.core.formatters.base import BaseFormatter

class MyFormatter(BaseFormatter):
    """Custom output formatter."""

    def format(self, results: list[PolicyValidationResult]) -> str:
        output = []
        for result in results:
            output.append(f"Policy: {result.policy_file}")
            for issue in result.issues:
                output.append(f"  - {issue.message}")
        return "\n".join(output)
```

### Built-in Formatters

| Formatter           | Use Case                          |
| ------------------- | --------------------------------- |
| `ConsoleFormatter`  | Terminal output with Rich styling |
| `EnhancedFormatter` | Enhanced console with details     |
| `JSONFormatter`     | Machine-readable output           |
| `MarkdownFormatter` | GitHub PR comments                |
| `SARIFFormatter`    | IDE/CI tool integration           |
| `CSVFormatter`      | Spreadsheet import                |
| `HTMLFormatter`     | Shareable reports                 |

---

## CLI Entry Point (`cli.py`)

```python
# Entry point: iam_validator/core/cli.py:main()

# Command registration
from iam_validator.commands import ALL_COMMANDS

parser = argparse.ArgumentParser(...)
subparsers = parser.add_subparsers(dest="command")

for command in ALL_COMMANDS:
    cmd_parser = subparsers.add_parser(command.name, ...)
    command.add_arguments(cmd_parser)

# Execution
args = parser.parse_args()
command = get_command(args.command)
await command.execute(args)
```

---

## Adding New Features

### New Formatter

1. Create `iam_validator/core/formatters/my_format.py`
2. Inherit from `BaseFormatter`
3. Register in formatter selection logic

### New Config Option

1. Add default in `config/defaults.py`
2. Update `ValidatorConfig` in `config/config_loader.py`
3. Update YAML schema documentation

### New Global Condition Key

1. Add to `config/aws_global_conditions.py`

### New Sensitive Action

1. Add to `config/sensitive_actions.py` with risk category

---

## Quick Search

```bash
# Find where model is defined
rg -n "class IAMPolicy" .

# Find check execution
rg -n "execute_checks_parallel" .

# Find config loading
rg -n "load_validator_config" .

# Find AWS API calls
rg -n "fetch_service" aws_service/

# Find formatter registration
rg -n "class.*Formatter" formatters/
```
