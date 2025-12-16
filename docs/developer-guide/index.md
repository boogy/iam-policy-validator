---
title: Developer Guide
description: Use IAM Policy Validator as a Python library
---

# Developer Guide

Use IAM Policy Validator programmatically in your Python applications.

<div class="grid cards" markdown>

-   :material-code-braces:{ .lg .middle } **Python SDK**

    ---

    Validate policies in your Python code

    [:octicons-arrow-right-24: SDK Guide](sdk/index.md)

-   :material-puzzle:{ .lg .middle } **Custom Checks**

    ---

    Write organization-specific validation rules

    [:octicons-arrow-right-24: Custom Checks](custom-checks/index.md)

-   :material-sitemap:{ .lg .middle } **Architecture**

    ---

    Understand the system design

    [:octicons-arrow-right-24: Architecture](architecture.md)

</div>

## Quick Example

```python
import asyncio
from iam_validator.sdk import validate_file

async def main():
    result = await validate_file("policy.json")

    if result.is_valid:
        print("Policy is valid!")
    else:
        for issue in result.issues:
            print(f"{issue.severity}: {issue.message}")

asyncio.run(main())
```
