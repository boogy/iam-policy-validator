# Check Documentation

**⚠️ This file has been deprecated and replaced with better documentation.**

The check documentation has been reorganized into the `docs/` folder with comprehensive examples showing how different configurations affect pass/fail behavior.

## 📖 New Documentation

### [Check Reference Guide](check-reference.md)
**Complete reference for all 18 checks with:**
- Configuration options for each check
- Pass/fail examples with actual policy JSON
- Explanation of why policies fail
- How to fix common issues
- Configuration strategies per environment

### [Condition Requirements](condition-requirements.md)
**Action condition enforcement documentation:**
- Available requirements (6 total)
- How to use Python API for customization
- Examples of condition enforcement
- Category-based sensitive actions

### [Privilege Escalation Detection](privilege-escalation.md)
**Understanding privilege escalation:**
- Common escalation paths
- How to detect them
- Configuration to prevent escalation

### [Example Configurations](../examples/configs/README.md)
**Ready-to-use configurations:**
- Development, CI/CD, Production configs
- Security audit configuration
- Resource policy validation
- Privilege escalation focus

## Why the Change?

The old CHECKS.md file:
- ❌ Was a flat list without proper organization
- ❌ Didn't show pass/fail examples
- ❌ Didn't explain configuration impact
- ❌ Mixed check docs with configuration info

The new documentation:
- ✅ Organized by check type (AWS validation vs security)
- ✅ Shows actual JSON examples with pass/fail
- ✅ Explains configuration options
- ✅ Demonstrates how configs affect behavior
- ✅ Includes quick reference tables
- ✅ Links to related documentation

## Migration Guide

If you were linking to this file, update your links:

| Old Link | New Link |
|----------|----------|
| `CHECKS.md` | [check-reference.md](check-reference.md) |
| `CHECKS.md#wildcard-action` | [check-reference.md#wildcard-action](check-reference.md#wildcard-action) |
| `CHECKS.md#sensitive-action` | [check-reference.md#sensitive-action](check-reference.md#sensitive-action) |
| `CHECKS.md#condition-enforcement` | [condition-requirements.md](condition-requirements.md) |
| Root `CHECKS.md` | Now at `docs/CHECKS.md` |

## Quick Links

- **[Complete Check Reference](check-reference.md)** - All 18 checks with examples
- **[Configuration Guide](configuration.md)** - How to configure the validator
- **[Example Configs](../examples/configs/README.md)** - Ready-to-use configurations
- **[README](../README.md)** - Main project documentation

---

**This file will be removed in a future version. Please update your bookmarks and links.**
