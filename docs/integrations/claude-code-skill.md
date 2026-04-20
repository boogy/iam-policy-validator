---
title: Claude Code Skill
description: Install IAM Policy Validator as a Claude Code skill (CLI-based, no MCP server required)
---

# Claude Code Skill

IAM Policy Validator ships a [Claude Code](https://docs.claude.com/en/docs/claude-code) skill that teaches Claude how to drive the `iam-validator` CLI to validate, audit, and query AWS IAM policies.

This is the **CLI-based alternative** to the [MCP server](mcp-server.md):

| Use the skill if…                                               | Use the MCP server if…                                      |
| --------------------------------------------------------------- | ----------------------------------------------------------- |
| You're using Claude Code (terminal / desktop / IDE extension)   | You're integrating with Claude Desktop or another MCP host  |
| You want zero-config install via the plugin marketplace         | You want programmatic tool access with 35+ structured tools |
| You already run `iam-validator` in CI and want the same UX here | You need the MCP's policy-generation templates              |

Both paths can coexist — installing one does not affect the other.

## Install

Add this repository as a Claude Code plugin marketplace, then install the plugin:

```text
/plugin marketplace add boogy/iam-policy-validator
/plugin install iam-policy-validator@iam-policy-validator
```

The first command registers the marketplace defined in [`.claude-plugin/marketplace.json`](https://github.com/boogy/iam-policy-validator/blob/main/.claude-plugin/marketplace.json). The second installs the plugin itself (the plugin name happens to match the marketplace name).

After install, restart Claude Code. The skill is now active in every session.

!!! note "Prerequisites"
    The skill invokes the `iam-validator` CLI. It will use whichever installation Claude Code has access to — typically one of:

    ```bash
    uvx iam-policy-validator ...   # recommended: no install
    uv add iam-policy-validator     # per project
    pipx install iam-policy-validator
    ```

    If the CLI is not available, the skill will ask before installing anything that changes your environment.

## What the skill does

When loaded, the skill triggers automatically on prompts like:

- "Validate this IAM policy" / "Check `policy.json`"
- "Find wildcards / privilege-escalation risks in my policies"
- "Audit this trust policy for confused deputy"
- "Run AWS Access Analyzer on this policy"
- "Which S3 actions exist / what condition keys does `kms` have?"
- "Post IAM findings to this PR"

Claude will pick the right subcommand (`validate`, `analyze`, `query`, `post-to-pr`, `sync-services`, `cache`) and choose sensible flags (e.g. `--policy-type TRUST_POLICY` for role trust docs, `--format sarif` when you ask for CI output).

## Updating

After pulling a new release of the validator:

```text
/plugin update iam-policy-validator@iam-policy-validator
```

The skill tracks CLI behavior rather than hardcoded internals, so minor/patch releases of `iam-policy-validator` will not require a skill update. Major releases that change CLI flags may require one — see the [CHANGELOG](../changelog.md).

## Uninstall

```text
/plugin uninstall iam-policy-validator@iam-policy-validator
/plugin marketplace remove iam-policy-validator
```

## Source

The skill lives in [`skills/iam-policy-validator/`](https://github.com/boogy/iam-policy-validator/tree/main/skills/iam-policy-validator) inside this repository. Contributions welcome — bug reports and CLI-flag corrections via [GitHub Issues](https://github.com/boogy/iam-policy-validator/issues).
