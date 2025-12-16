---
title: CLI Reference
description: Complete command-line interface documentation
---

# CLI Reference

Complete documentation for the `iam-validator` command-line interface.

## Commands

| Command | Description |
|---------|-------------|
| `validate` | Validate IAM policies |
| `analyze` | AWS Access Analyzer integration |
| `post-to-pr` | Post results to GitHub PR |
| `query` | Query AWS service definitions |
| `cache` | Manage AWS service cache |
| `download-services` | Download AWS definitions for offline use |
| `completion` | Generate shell completion scripts |

## validate

Validate IAM policies for correctness and security issues.

### Usage

```bash
iam-validator validate [OPTIONS]
```

### Options

| Option | Description | Default |
|--------|-------------|---------|
| `--path`, `-p` | Path to policy file or directory | Required |
| `--config`, `-c` | Path to configuration file | Auto-detect |
| `--format`, `-f` | Output format | `console` |
| `--policy-type` | Policy type | `IDENTITY_POLICY` |
| `--fail-on-warnings` | Fail on warnings | `false` |
| `--verbose`, `-v` | Verbose output | `false` |

### Examples

```bash
# Validate a single file
iam-validator validate --path policy.json

# Validate a directory
iam-validator validate --path ./policies/

# With custom config
iam-validator validate --path ./policies/ --config iam-validator.yaml

# JSON output
iam-validator validate --path policy.json --format json

# Trust policy validation
iam-validator validate --path trust-policy.json --policy-type TRUST_POLICY
```

### Output Formats

| Format | Description |
|--------|-------------|
| `console` | Rich terminal output (default) |
| `enhanced` | Colorful detailed output |
| `json` | Machine-readable JSON |
| `sarif` | SARIF for security tools |
| `markdown` | Markdown report |
| `html` | HTML report |
| `csv` | CSV export |

## query

Query AWS service definitions for actions, ARNs, and condition keys.

### Usage

```bash
iam-validator query <subcommand> [OPTIONS]
```

### Subcommands

#### query action

```bash
# List all S3 actions
iam-validator query action --service s3

# Filter by access level
iam-validator query action --service iam --access-level permissions-management

# Get specific action
iam-validator query action --service s3 --name GetObject
```

#### query arn

```bash
# List ARN formats
iam-validator query arn --service s3

# Specific resource type
iam-validator query arn --service s3 --name bucket
```

#### query condition

```bash
# List condition keys
iam-validator query condition --service s3
```

## cache

Manage the AWS service definition cache.

### Usage

```bash
# Show cache info
iam-validator cache info

# Clear cache
iam-validator cache clear
```

## download-services

Download AWS service definitions for offline validation.

### Usage

```bash
# Download all services
iam-validator download-services

# Download specific services
iam-validator download-services --services s3,iam,ec2
```

## completion

Generate shell completion scripts.

### Usage

```bash
# Bash
eval "$(iam-validator completion bash)"

# Zsh
eval "$(iam-validator completion zsh)"

# Fish
iam-validator completion fish | source
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success - all policies valid |
| 1 | Validation errors found |
| 2 | Configuration or input error |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `IAM_VALIDATOR_CONFIG` | Default config file path |
| `IAM_VALIDATOR_CACHE_DIR` | Cache directory location |
| `NO_COLOR` | Disable colored output |
