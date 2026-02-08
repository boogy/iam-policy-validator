# AGENTS.md - AI Coding Agent Instructions

This project maintains detailed development instructions in `CLAUDE.md` files throughout
the repository. These files are standard markdown and work with any AI coding agent.

If there’s a conflict, treat CLAUDE.md as authoritative.

## Getting Started

Read the root **[CLAUDE.md](CLAUDE.md)** first — it contains all project rules, commands,
architecture, and conventions.

## Subdirectory Context

When working in a specific directory, read its local `CLAUDE.md` for specialized guidance:

| Directory                     | CLAUDE.md                                         | Context                          |
| ----------------------------- | ------------------------------------------------- | -------------------------------- |
| `iam_validator/core/`         | [CLAUDE.md](iam_validator/core/CLAUDE.md)         | Validation engine architecture   |
| `iam_validator/checks/`       | [CLAUDE.md](iam_validator/checks/CLAUDE.md)       | Check development patterns       |
| `iam_validator/mcp/`          | [CLAUDE.md](iam_validator/mcp/CLAUDE.md)          | MCP server tools and templates   |
| `iam_validator/sdk/`          | [CLAUDE.md](iam_validator/sdk/CLAUDE.md)          | SDK usage and extension          |
| `iam_validator/commands/`     | [CLAUDE.md](iam_validator/commands/CLAUDE.md)     | CLI command patterns             |
| `iam_validator/integrations/` | [CLAUDE.md](iam_validator/integrations/CLAUDE.md) | GitHub PR posting, MS Teams      |
| `tests/`                      | [CLAUDE.md](tests/CLAUDE.md)                      | Testing patterns and fixtures    |
| `docs/`                       | [CLAUDE.md](docs/CLAUDE.md)                       | MkDocs documentation conventions |

## Reusable Workflows

This project includes pre-built workflow instructions in `.claude/commands/`. These are
plain markdown files that any AI agent can read and follow — not Claude Code specific.

To use a workflow: read the corresponding file and follow its instructions, replacing
`$ARGUMENTS` with the user's input.

| Workflow            | File                                                                               | Purpose                                          |
| ------------------- | ---------------------------------------------------------------------------------- | ------------------------------------------------ |
| **Add Check**       | [`.claude/commands/add-check.md`](.claude/commands/add-check.md)                   | Scaffold a new IAM policy validation check       |
| **Test Check**      | [`.claude/commands/test-check.md`](.claude/commands/test-check.md)                 | Run tests for a specific check                   |
| **Debug Check**     | [`.claude/commands/debug-check.md`](.claude/commands/debug-check.md)               | Debug a specific check with verbose output       |
| **Run Check**       | [`.claude/commands/run-check.md`](.claude/commands/run-check.md)                   | Validate a policy file                           |
| **Review**          | [`.claude/commands/review.md`](.claude/commands/review.md)                         | Comprehensive code review of recent changes      |
| **Fix Issue**       | [`.claude/commands/fix-issue.md`](.claude/commands/fix-issue.md)                   | Analyze and fix a GitHub issue                   |
| **Create PR**       | [`.claude/commands/create-pr.md`](.claude/commands/create-pr.md)                   | Create a pull request with current changes       |
| **Version Tag**     | [`.claude/commands/create-version-tag.md`](.claude/commands/create-version-tag.md) | Bump version and create annotated tag            |
| **Benchmark**       | [`.claude/commands/benchmark.md`](.claude/commands/benchmark.md)                   | Run performance benchmarks                       |
| **Generate Policy** | [`.claude/commands/generate-policy.md`](.claude/commands/generate-policy.md)       | Generate IAM policy from template or description |

**Example**: If the user asks "scaffold a new check called `vpc_restriction`", read
`.claude/commands/add-check.md` and follow its steps with `$ARGUMENTS = vpc_restriction`.

## Minimum Essentials

If you can only read one file, read [CLAUDE.md](CLAUDE.md). The critical rules are:

- Run `uv run ruff check` and `uv run ruff format` before committing
- Run `uv run pytest` for changes to core logic
- Use type hints for all public functions
- Use Conventional Commits (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`)
- Never commit secrets, API keys, or credentials
- Create pull requests instead of pushing to `main` directly
