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
settings:
  custom_checks_dir: "./my-checks"

checks:
  mfa_required:
    enabled: true
    severity: high
```
