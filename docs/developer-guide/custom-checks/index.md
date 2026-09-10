---
title: Custom Checks
description: Write organization-specific validation rules
---

# Custom Checks

Create custom validation checks for organization-specific policies and compliance requirements.

## Overview

Custom checks allow you to:

- Enforce organization-specific security policies
- Implement compliance requirements (SOC2, PCI-DSS, HIPAA)
- Add business logic validation
- Share rules across teams

## Topics

- [Tutorial](tutorial.md) — Step-by-step guide to creating checks
- [Examples](examples.md) — Real-world check examples
- [Best Practices](best-practices.md) — Tips for writing effective checks

## Quick Example

```python
from typing import ClassVar

from iam_validator.core.check_registry import PolicyCheck, CheckConfig
from iam_validator.core.aws_service import AWSServiceFetcher
from iam_validator.core.models import Statement, ValidationIssue


class MFARequiredCheck(PolicyCheck):
    """Ensures sensitive actions require MFA authentication."""

    check_id: ClassVar[str] = "mfa_required"
    description: ClassVar[str] = "Ensures sensitive actions require MFA"
    default_severity: ClassVar[str] = "high"

    async def execute(
        self,
        statement: Statement,
        statement_idx: int,
        fetcher: AWSServiceFetcher,
        config: CheckConfig,
    ) -> list[ValidationIssue]:
        issues = []

        if statement.effect != "Allow":
            return issues

        # Your check logic here

        return issues
```

## Configuration

Enable custom checks in `iam-validator.yaml`:

```yaml
custom_checks_dir: "./my-checks"

checks:
  mfa_required:
    enabled: true
    severity: high
```

!!! danger "Custom check directories execute arbitrary Python"

    Every `.py` file in the directory is imported and executed. Only point
    `custom_checks_dir` / `--custom-checks-dir` at code you trust, and never
    enable custom checks in workflows that run on untrusted forks (e.g.
    `pull_request_target`), where an attacker can modify the checked-out code.

    A `custom_checks_dir` set **only** in the YAML config file is ignored
    unless you also pass `--allow-config-custom-checks` (or an explicit
    `--custom-checks-dir`) — the config file often lives in the same
    repository as the untrusted policies being validated, so its presence
    alone is not treated as consent to execute code.

## Entry-Point Plugin Discovery

Third-party packages can advertise checks under the `iam_validator.checks` entry-point
group instead of (or in addition to) `custom_checks_dir`. `create_default_registry()`
discovers and registers them automatically — no config flag or CLI argument required.

```toml
# pyproject.toml of a third-party package
[project.entry-points."iam_validator.checks"]
mfa_required = "my_package.checks:MFARequiredCheck"
```

Once the package is installed in the same environment as `iam-validator`, its checks
show up alongside the built-in ones. An entry point that fails to load, resolves to
something that isn't a `PolicyCheck`, or declares a `check_id` that duplicates an
already-registered check is logged and skipped — it does not abort discovery of the
other entry points, and it does not shadow the existing check.

!!! danger "Discovery is unconditional — there is no opt-out flag"

    Unlike `custom_checks_dir` (gated behind `--custom-checks-dir` /
    `--allow-config-custom-checks`, with a warning in `--help`), entry-point discovery
    has no equivalent flag. Any package installed in the environment that advertises
    the `iam_validator.checks` entry-point group has its code loaded and executed as soon
    as `create_default_registry()` builds a registry — which the CLI, the SDK and the MCP
    server all do, including for commands that don't otherwise touch custom checks, and
    even when `include_builtin_checks=False`. Only install packages you trust into an
    environment that runs this validator.
