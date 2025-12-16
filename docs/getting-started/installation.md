---
title: Installation
description: Install IAM Policy Validator using pip, uv, or pipx
---

# Installation

IAM Policy Validator can be installed using several methods. Choose the one that best fits your workflow.

## Requirements

- **Python 3.10 or higher**
- **pip, uv, or pipx** for installation

## Installation Methods

### pip (Recommended)

The simplest way to install:

```bash
pip install iam-policy-validator
```

### uv (Fast)

If you use [uv](https://github.com/astral-sh/uv) for faster Python package management:

```bash
uv add iam-policy-validator
```

Or install globally:

```bash
uv tool install iam-policy-validator
```

### pipx (Isolated)

For isolated installation that doesn't affect your global Python:

```bash
pipx install iam-policy-validator
```

### From Source

For the latest development version:

```bash
git clone https://github.com/boogy/iam-policy-validator.git
cd iam-policy-validator
pip install -e .
```

## Verify Installation

After installation, verify it works:

```bash
iam-validator --version
```

You should see output like:

```
iam-validator 1.14.1
```

## Shell Completion

Enable shell completion for a better CLI experience:

=== "Bash"

    ```bash
    # Add to ~/.bashrc
    eval "$(iam-validator completion bash)"
    ```

=== "Zsh"

    ```bash
    # Add to ~/.zshrc
    eval "$(iam-validator completion zsh)"
    ```

=== "Fish"

    ```bash
    # Add to ~/.config/fish/config.fish
    iam-validator completion fish | source
    ```

## Upgrading

To upgrade to the latest version:

```bash
pip install --upgrade iam-policy-validator
```

## Uninstalling

To remove IAM Policy Validator:

```bash
pip uninstall iam-policy-validator
```

## Troubleshooting

### Command Not Found

If `iam-validator` is not found after installation:

1. **Check your PATH** — Ensure `~/.local/bin` is in your PATH
2. **Restart your terminal** — Some changes require a new shell session
3. **Use full path** — Try `python -m iam_validator.core.cli`

### Permission Errors

If you get permission errors:

```bash
# Use --user flag
pip install --user iam-policy-validator

# Or use a virtual environment
python -m venv .venv
source .venv/bin/activate
pip install iam-policy-validator
```

### Python Version Issues

IAM Policy Validator requires Python 3.10+. Check your version:

```bash
python --version
```

If you have multiple Python versions, specify the correct one:

```bash
python3.10 -m pip install iam-policy-validator
```

## Next Steps

- [:octicons-arrow-right-24: Quick Start](quickstart.md) — Validate your first policy
- [:octicons-arrow-right-24: CLI Reference](../user-guide/cli-reference.md) — Full command documentation
