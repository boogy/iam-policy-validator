---
title: Output Formats
description: Available output formats for validation results
---

# Output Formats

IAM Policy Validator supports multiple output formats for different use cases.

## Available Formats

| Format | Flag | Use Case |
|--------|------|----------|
| Console | `--format console` | Interactive terminal (default) |
| Enhanced | `--format enhanced` | Colorful detailed output |
| JSON | `--format json` | Automation and parsing |
| SARIF | `--format sarif` | Security tools integration |
| Markdown | `--format markdown` | Documentation |
| HTML | `--format html` | Reports and sharing |
| CSV | `--format csv` | Spreadsheet analysis |

## Console (Default)

Rich terminal output with colors and formatting.

```bash
iam-validator validate --path policy.json
```

## Enhanced

More detailed colorful output with expanded information.

```bash
iam-validator validate --path policy.json --format enhanced
```

## JSON

Machine-readable JSON for automation.

```bash
iam-validator validate --path policy.json --format json
```

```json
{
  "summary": {
    "total_policies": 1,
    "valid_policies": 0,
    "invalid_policies": 1,
    "total_issues": 2
  },
  "results": [...]
}
```

## SARIF

Static Analysis Results Interchange Format for security tools.

```bash
iam-validator validate --path policy.json --format sarif > results.sarif
```

Compatible with:

- GitHub Code Scanning
- VS Code SARIF Viewer
- Azure DevOps
- Many security platforms

## Markdown

Markdown format for documentation and PRs.

```bash
iam-validator validate --path policy.json --format markdown
```

## HTML

HTML report for sharing and archiving.

```bash
iam-validator validate --path policy.json --format html > report.html
```

## CSV

CSV export for spreadsheet analysis.

```bash
iam-validator validate --path ./policies/ --format csv > issues.csv
```
