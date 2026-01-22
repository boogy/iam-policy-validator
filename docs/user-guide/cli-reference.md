---
title: CLI Reference
description: Complete command-line interface documentation
---

# CLI Reference

Complete documentation for the `iam-validator` command-line interface.

## Commands

| Command             | Description                                   |
| ------------------- | --------------------------------------------- |
| `validate`          | Validate IAM policies                         |
| `analyze`           | AWS Access Analyzer integration               |
| `post-to-pr`        | Post results to GitHub PR                     |
| `query`             | Query AWS service definitions                 |
| `cache`             | Manage AWS service cache                      |
| `download-services` | Download AWS definitions for offline use      |
| `completion`        | Generate shell completion scripts             |
| `mcp`               | Start MCP server for AI assistant integration |

## validate

Validate IAM policies for correctness and security issues.

### Usage

```bash
iam-validator validate [OPTIONS]
```

### Options

| Option               | Description                      | Default           |
| -------------------- | -------------------------------- | ----------------- |
| `--path`, `-p`       | Path to policy file or directory | Required          |
| `--config`, `-c`     | Path to configuration file       | Auto-detect       |
| `--format`, `-f`     | Output format                    | `console`         |
| `--policy-type`      | Policy type                      | `IDENTITY_POLICY` |
| `--fail-on-warnings` | Fail on warnings                 | `false`           |
| `--verbose`, `-v`    | Verbose output                   | `false`           |

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

| Format     | Description                    |
| ---------- | ------------------------------ |
| `console`  | Rich terminal output (default) |
| `enhanced` | Colorful detailed output       |
| `json`     | Machine-readable JSON          |
| `sarif`    | SARIF for security tools       |
| `markdown` | Markdown report                |
| `html`     | HTML report                    |
| `csv`      | CSV export                     |

## query

Query AWS service definitions for actions, ARNs, and condition keys.

### Usage

```bash
iam-validator query <subcommand> [OPTIONS]
```

### Options

The `--service` option is **optional** when `--name` includes the service prefix (e.g., `s3:GetObject`).

| Option                  | Description                                                                                |
| ----------------------- | ------------------------------------------------------------------------------------------ |
| `--service`             | AWS service prefix (optional if `--name` has prefix)                                       |
| `--name`                | Name(s) to query; supports multiple values, wildcards, and service prefix (`s3:GetObject`) |
| `--output`              | Output format: `json`, `yaml`, or `text`                                                   |
| `--show-condition-keys` | Show only condition keys for each action                                                   |
| `--show-resource-types` | Show only resource types for each action                                                   |
| `--show-access-level`   | Show only access level for each action                                                     |

### Subcommands

#### query action

```bash
# List all S3 actions
iam-validator query action --service s3

# Filter by access level
iam-validator query action --service iam --access-level permissions-management

# Get specific action (two equivalent forms)
iam-validator query action --service s3 --name GetObject
iam-validator query action --name s3:GetObject

# Query with service prefix in --name (--service not required)
iam-validator query action --name iam:CreateRole
iam-validator query action --name ec2:DescribeInstances --output yaml

# Filter write-level actions
iam-validator query action --service s3 --access-level write --output text

# Expand wildcard patterns to matching actions
iam-validator query action --name "iam:Get*" --output text
iam-validator query action --name "s3:*Object*" --output json
iam-validator query action --service ec2 --name "Describe*" --output text

# Count matching actions
iam-validator query action --name "ec2:Describe*" --output text | wc -l

# Query MULTIPLE actions at once (space-separated)
iam-validator query action --name dynamodb:Query dynamodb:Scan --output yaml
iam-validator query action --name s3:GetObject s3:PutObject ec2:DescribeInstances

# Mix exact names and wildcards
iam-validator query action --name dynamodb:Query dynamodb:BatchGet* --output json
iam-validator query action --name iam:CreateRole iam:Delete* --output text
```

##### Multiple Action Queries

The `--name` option accepts multiple space-separated action names, allowing you to query several actions in a single command:

```bash
# Query multiple specific actions
iam-validator query action --name dynamodb:Query dynamodb:Scan --output yaml

# Query actions across different services
iam-validator query action --name s3:GetObject ec2:DescribeInstances iam:GetRole

# Mix exact names with wildcards for powerful queries
iam-validator query action --name dynamodb:Query dynamodb:BatchGet* --output json
iam-validator query action --name iam:CreateRole iam:Delete* --output text
```

This feature is optimized for performance:

- Actions are grouped by service to minimize API calls
- Service definitions are fetched in parallel when querying multiple services
- Wildcards and exact matches are processed efficiently in a single pass

##### Wildcard Pattern Expansion

The `--name` option supports wildcard patterns (`*` and `?`) to find all matching actions:

- `*` matches zero or more characters
- `?` matches exactly one character

This is useful for:

- Exploring available actions for a permission prefix
- Finding all actions related to a specific operation
- Generating action lists for least-privilege policies

```bash
# Find all IAM Get actions
iam-validator query action --name "iam:Get*" --output text
# Output: iam:GetAccessKeyLastUsed, iam:GetAccountAuthorizationDetails, ...

# Find all S3 Object-related actions
iam-validator query action --name "s3:*Object*" --output text
# Output: s3:DeleteObject, s3:GetObject, s3:PutObject, ...

# Get detailed JSON output for wildcard results
iam-validator query action --name "iam:Create*" --output json
```

##### Output Field Filters

Use `--show-condition-keys`, `--show-resource-types`, or `--show-access-level` to filter output to only specific fields:

```bash
# Show only condition keys for DynamoDB actions
iam-validator query action --name dynamodb:Query dynamodb:Scan --show-condition-keys --output yaml

# Show only resource types for S3 wildcard actions
iam-validator query action --name "s3:Get*" --show-resource-types --output text

# Show only access level for multiple actions
iam-validator query action --name iam:CreateRole iam:DeleteRole --show-access-level

# Combine multiple filters
iam-validator query action --name s3:GetObject --show-condition-keys --show-resource-types --output yaml
```

These filters work with all query modes (single action, multiple actions, wildcards) and all output formats.

#### query arn

```bash
# List ARN formats
iam-validator query arn --service s3

# Specific resource type (two equivalent forms)
iam-validator query arn --service s3 --name bucket
iam-validator query arn --name s3:bucket

# Get ARN format for IAM role
iam-validator query arn --name iam:role
```

#### query condition

```bash
# List condition keys
iam-validator query condition --service s3

# Query specific condition key (two equivalent forms)
iam-validator query condition --service s3 --name prefix
iam-validator query condition --name s3:prefix
```

## cache

Manage the AWS service definition cache.

### Usage

```bash
iam-validator cache <subcommand> [OPTIONS]
```

### Subcommands

| Subcommand | Description                                      |
| ---------- | ------------------------------------------------ |
| `info`     | Show cache information and statistics            |
| `list`     | List all cached AWS services                     |
| `clear`    | Clear all cached AWS service definitions         |
| `refresh`  | Refresh all cached services with fresh data      |
| `prefetch` | Pre-fetch common AWS services (without clearing) |
| `location` | Show cache directory location                    |

### Examples

```bash
# Show cache info
iam-validator cache info

# List all cached services
iam-validator cache list
iam-validator cache list --format table

# Clear cache completely
iam-validator cache clear

# Refresh all cached services with fresh data from AWS
iam-validator cache refresh

# Pre-fetch common AWS services
iam-validator cache prefetch

# Show cache directory location
iam-validator cache location
```

### Options

| Option     | Subcommand | Description                                 |
| ---------- | ---------- | ------------------------------------------- |
| `--config` | all        | Path to configuration file                  |
| `--format` | `list`     | Output format: `table`, `columns`, `simple` |

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

## mcp

Start an MCP (Model Context Protocol) server for AI assistant integration.

### Usage

```bash
iam-validator mcp [OPTIONS]
```

### Options

| Option            | Description                           | Default     |
| ----------------- | ------------------------------------- | ----------- |
| `--transport`     | Transport protocol (`stdio` or `sse`) | `stdio`     |
| `--host`          | Host for SSE transport                | `127.0.0.1` |
| `--port`          | Port for SSE transport                | `8000`      |
| `--config`        | Path to configuration YAML file       | None        |
| `--verbose`, `-v` | Enable verbose logging                | `false`     |

### Examples

```bash
# Start with stdio transport (for Claude Desktop)
iam-validator mcp

# Start with SSE transport
iam-validator mcp --transport sse --host 127.0.0.1 --port 8000

# Start with config preloaded
iam-validator mcp --config ./config.yaml
```

See the [MCP Server Integration](../integrations/mcp-server.md) guide for detailed setup instructions.

## Exit Codes

| Code | Meaning                      |
| ---- | ---------------------------- |
| 0    | Success - all policies valid |
| 1    | Validation errors found      |
| 2    | Configuration or input error |

## Environment Variables

| Variable                  | Description              |
| ------------------------- | ------------------------ |
| `IAM_VALIDATOR_CONFIG`    | Default config file path |
| `IAM_VALIDATOR_CACHE_DIR` | Cache directory location |
| `NO_COLOR`                | Disable colored output   |
