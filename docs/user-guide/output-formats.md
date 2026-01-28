---
title: Output Formats
description: Available output formats for validation results
---

# Output Formats

IAM Policy Validator supports multiple output formats for different use cases.

## Available Formats

| Format   | Flag                | Use Case                       |
| -------- | ------------------- | ------------------------------ |
| Console  | `--format console`  | Interactive terminal (default) |
| Enhanced | `--format enhanced` | Colorful detailed output       |
| JSON     | `--format json`     | Automation and parsing         |
| SARIF    | `--format sarif`    | Security tools integration     |
| Markdown | `--format markdown` | Documentation                  |
| HTML     | `--format html`     | Reports and sharing            |
| CSV      | `--format csv`      | Spreadsheet analysis           |

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

**Sample Output:**

```json
{
  "summary": {
    "total_policies": 1,
    "valid_policies": 0,
    "invalid_policies": 1,
    "total_issues": 2,
    "issues_by_severity": {
      "high": 1,
      "medium": 1
    }
  },
  "results": [
    {
      "policy_file": "policy.json",
      "is_valid": false,
      "issues": [
        {
          "severity": "high",
          "issue_type": "service_wildcard",
          "message": "Statement uses service wildcard 'iam:*' which grants all IAM permissions",
          "statement_index": 0,
          "action": "iam:*",
          "suggestion": "Replace with specific actions needed for your use case"
        },
        {
          "severity": "medium",
          "issue_type": "wildcard_resource",
          "message": "Statement applies to all resources (*)",
          "statement_index": 0,
          "suggestion": "Replace wildcard with specific resource ARNs"
        }
      ]
    }
  ]
}
```

**Use Cases:**

- CI/CD pipelines that parse results programmatically
- Integration with monitoring and alerting systems
- Custom reporting tools and dashboards
- Storing results in databases for historical analysis

## SARIF

Static Analysis Results Interchange Format for security tools.

```bash
iam-validator validate --path policy.json --format sarif > results.sarif
```

**Sample Output:**

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "iam-policy-validator",
          "informationUri": "https://github.com/boogy/iam-policy-validator",
          "rules": [
            {
              "id": "service_wildcard",
              "name": "ServiceWildcard",
              "shortDescription": {
                "text": "Checks for service-level wildcards"
              },
              "defaultConfiguration": {
                "level": "error"
              }
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "service_wildcard",
          "level": "error",
          "message": {
            "text": "Statement uses service wildcard 'iam:*'"
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "policy.json"
                },
                "region": {
                  "startLine": 5
                }
              }
            }
          ]
        }
      ]
    }
  ]
}
```

**Compatible with:**

- GitHub Code Scanning (upload with `github/codeql-action/upload-sarif`)
- VS Code SARIF Viewer extension
- Azure DevOps Security Dashboard
- SonarQube and other security platforms

**Use Cases:**

- GitHub Security tab integration for pull request checks
- Centralized security scanning dashboards
- IDE integration for real-time feedback
- Compliance reporting with standardized format

## Markdown

Markdown format for documentation and PRs.

```bash
iam-validator validate --path policy.json --format markdown
```

**Sample Output:**

```markdown
# IAM Policy Validation Report

## Summary

| Metric | Value |
|--------|-------|
| Total Policies | 1 |
| Valid Policies | 0 |
| Invalid Policies | 1 |
| Total Issues | 2 |

## Results

### policy.json

**Status:** Invalid

#### Issues

| Severity | Type | Message |
|----------|------|---------|
| high | service_wildcard | Statement uses service wildcard 'iam:*' which grants all IAM permissions |
| medium | wildcard_resource | Statement applies to all resources (*) |

**Suggestions:**

- Replace `iam:*` with specific actions needed for your use case
- Replace wildcard with specific resource ARNs
```

**Use Cases:**

- GitHub Pull Request comments (via `--github-comment` flag)
- Documentation generation for policy audits
- Embedding results in wiki pages or READMEs
- Email reports for stakeholders

## HTML

HTML report for sharing and archiving.

```bash
iam-validator validate --path policy.json --format html > report.html
```

**Features:**

- Self-contained HTML file (no external dependencies)
- Collapsible sections for large reports
- Color-coded severity indicators
- Sortable issue tables
- Print-friendly styling

**Use Cases:**

- Sharing validation results with non-technical stakeholders
- Archiving compliance reports for audits
- Embedding in internal documentation portals
- Generating periodic security assessment reports

## CSV

CSV export for spreadsheet analysis.

```bash
iam-validator validate --path ./policies/ --format csv > issues.csv
```

**Sample Output:**

```csv
policy_file,statement_index,severity,issue_type,message,action,resource,suggestion
policy.json,0,high,service_wildcard,"Statement uses service wildcard 'iam:*'",iam:*,*,"Replace with specific actions"
policy.json,0,medium,wildcard_resource,"Statement applies to all resources (*)","",*,"Replace with specific ARNs"
admin-policy.json,1,critical,full_wildcard,"Statement allows all actions on all resources",*,*,"Apply least-privilege"
```

**Use Cases:**

- Import into Excel, Google Sheets, or other spreadsheet tools
- Data analysis and trend tracking over time
- Bulk issue triage and assignment
- Integration with ticketing systems (Jira, ServiceNow)
- Creating pivot tables for executive summaries

## Format Selection Guide

| Format   | Best For                                           | Output Destination       |
| -------- | -------------------------------------------------- | ------------------------ |
| Console  | Interactive development and debugging              | Terminal                 |
| Enhanced | Detailed review with context                       | Terminal                 |
| JSON     | CI/CD pipelines, automation, APIs                  | Files, stdout            |
| SARIF    | GitHub Security, IDE integration, security tools   | Files, GitHub Actions    |
| Markdown | Pull request comments, documentation               | GitHub, wikis, docs      |
| HTML     | Reports for stakeholders, compliance audits        | Browser, email, archives |
| CSV      | Spreadsheet analysis, bulk processing, data export | Excel, databases         |
