# Commands Module

8 CLI subcommands. Extends [../../CLAUDE.md](../../CLAUDE.md).

---

## Adding a command

1. Create `iam_validator/commands/my_command.py` inheriting from `Command` (see `base.py`):
   implement `name`, `description`, `add_arguments(parser)`, `async execute(args) -> int`.
2. Append the instance to `ALL_COMMANDS` in `iam_validator/commands/__init__.py`.
3. Add bash + zsh stubs to `iam_validator/commands/completion.py`.
4. Test in `tests/commands/test_my_command.py`.

Inside `execute()`, return `0` on success, non-zero on failure. Use Rich (`rich.console.Console`,
`rich.table.Table`, `rich.progress.Progress`) for terminal output.

---

## Existing commands

| Command         | File                   | Purpose                          |
| --------------- | ---------------------- | -------------------------------- |
| `validate`      | `validate.py`          | main validation entry point      |
| `analyze`       | `analyze.py`           | AWS Access Analyzer integration  |
| `post-to-pr`    | `post_to_pr.py`        | post a saved report to a PR      |
| `cache`         | `cache.py`             | manage AWS service-data cache    |
| `sync-services` | `download_services.py` | offline AWS definitions download |
| `query`         | `query.py`             | query AWS service definitions    |
| `completion`    | `completion.py`        | bash / zsh completion scripts    |
| `mcp`           | `mcp.py`               | launch the MCP server            |

`validate.py` is the largest — it orchestrates streaming mode, PR commenting, label
management, and per-file policy-type resolution. When in doubt, mirror its patterns.

---

## Conventions

- Commands are async; share an `AWSServiceFetcher` via `async with` rather than per-call.
- Long-running flows must support both batch and streaming validation modes
  (`_execute_streaming` in `validate.py`).
- Argument names that map to YAML config use the same key (e.g. `--policy-type` →
  `policy_type:`).
- When a command posts to GitHub, use `iam_validator/integrations/github_integration.py`
  rather than reimplementing API calls.
