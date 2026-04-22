# Output Formats

Select with `--format <name>`. Write to a file with `--output <path>`.

| Format     | Use it for                                  |
| ---------- | ------------------------------------------- |
| `console`  | Interactive terminal (default, Rich-styled) |
| `enhanced` | Extra-detailed terminal output              |
| `json`     | Machine parsing, CI artifacts               |
| `sarif`    | GitHub code scanning, IDE integration       |
| `markdown` | PR comments, Slack snippets, reports        |
| `html`     | Shareable standalone report                 |
| `csv`      | Spreadsheet import, dashboards              |

## Examples

```bash
# SARIF for GitHub code scanning
iam-validator validate --path ./policies/ \
  --format sarif --output iam-findings.sarif

# Markdown for copy-paste into a PR
iam-validator validate --path policy.json \
  --format markdown --output findings.md

# HTML report
iam-validator validate --path ./policies/ \
  --format html --output iam-report.html
```

## Tips

- SARIF is the right pick for CI → GitHub Security tab.
- Markdown is what the `post-to-pr` subcommand emits; if you already use `post-to-pr` you don't need to generate it separately.
- `json` output is stable enough to parse with `jq`; schema docs: https://boogy.github.io/iam-policy-validator/user-guide/output-formats/
