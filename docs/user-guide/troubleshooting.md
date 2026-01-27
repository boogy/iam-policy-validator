---
title: Troubleshooting
description: Common issues and solutions
---

# Troubleshooting

Solutions to common issues with IAM Policy Validator.

## Installation Issues

### Command Not Found

If `iam-validator` is not found after installation:

```bash
# Check if installed
pip show iam-policy-validator

# Ensure ~/.local/bin is in PATH
export PATH="$HOME/.local/bin:$PATH"

# Or use Python module directly
python -m iam_validator.core.cli validate --path policy.json
```

### Permission Denied

```bash
# Use --user flag
pip install --user iam-policy-validator

# Or use virtual environment
python -m venv .venv
source .venv/bin/activate
pip install iam-policy-validator
```

## Validation Issues

### No Policies Found

```bash
# Check file extension
ls -la *.json *.yaml

# Use verbose mode
iam-validator validate --path ./policies/ --verbose
```

### Invalid JSON

If you get JSON parsing errors:

1. Validate JSON syntax with `jq`:

   ```bash
   jq . policy.json
   ```

2. Check for trailing commas (not allowed in JSON)

3. Ensure proper encoding (UTF-8)

### Action Not Found

If valid actions are reported as invalid:

```bash
# Update AWS service cache
iam-validator cache clear
iam-validator download-services
```

## Performance Issues

### Slow Validation

For large policy sets:

```bash
# Pre-download service definitions
iam-validator download-services

# Use JSON output (faster than enhanced)
iam-validator validate --path ./policies/ --format json
```

### High Memory Usage

For very large directories:

```bash
# Validate in batches
find ./policies -name "*.json" | xargs -n 10 iam-validator validate --path
```

## GitHub Actions Issues

### Rate Limiting

GitHub API rate limits can affect PR comments:

```yaml
- uses: boogy/iam-policy-validator@v1
  with:
    github-token: ${{ secrets.GITHUB_TOKEN }}
    # Token has higher rate limits than unauthenticated
```

### Comments Not Appearing

Check workflow permissions:

```yaml
permissions:
  contents: read
  pull-requests: write
```

## Getting Help

- [:fontawesome-brands-github: GitHub Issues](https://github.com/boogy/iam-policy-validator/issues)
- [:fontawesome-brands-github: GitHub Discussions](https://github.com/boogy/iam-policy-validator/discussions)
