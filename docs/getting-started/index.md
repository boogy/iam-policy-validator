---
title: Getting Started
description: Get started with IAM Policy Validator in 5 minutes
---

# Getting Started

Get up and running with IAM Policy Validator in under 5 minutes.

<div class="grid cards" markdown>

-   :material-download:{ .lg .middle } **Installation**

    ---

    Install via pip, uv, or pipx

    [:octicons-arrow-right-24: Install](installation.md)

-   :material-rocket-launch:{ .lg .middle } **Quick Start**

    ---

    Validate your first policy in seconds

    [:octicons-arrow-right-24: Quick Start](quickstart.md)

-   :material-school:{ .lg .middle } **First Validation**

    ---

    Step-by-step tutorial with explanations

    [:octicons-arrow-right-24: Tutorial](first-validation.md)

</div>

## Prerequisites

- **Python 3.10+** — Required for all installation methods
- **pip, uv, or pipx** — Package manager of your choice

## Fastest Path

```bash
# Install
pip install iam-policy-validator

# Validate
iam-validator validate --path policy.json
```

That's it! You're ready to validate IAM policies.

## What's Next?

After installation, you can:

1. **[Configure validation rules](../user-guide/configuration.md)** — Customize checks for your organization
2. **[Set up GitHub Actions](../integrations/github-actions.md)** — Automate validation in CI/CD
3. **[Use the Python SDK](../developer-guide/sdk/index.md)** — Integrate into your applications
4. **[Write custom checks](../developer-guide/custom-checks/index.md)** — Add organization-specific rules
