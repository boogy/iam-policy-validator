# IAM Policy Validator - Claude Code Instructions

Python 3.10–3.14 CLI + GitHub Action + Python SDK + MCP server for validating AWS IAM
policies. Plugin-based check system with async parallel execution. uv, Pydantic v2,
httpx (HTTP/2), boto3, Rich, FastMCP.

This file is authoritative. Subdirectory `CLAUDE.md` files extend it.

---

## CRITICAL RULES (MUST)

### Process

- **MUST** write plans to `.claude/plans/`
- **MUST** ask for explicit consent before `git push` (and use `--force-with-lease`, never `--force` to main)
- **MUST** create PRs instead of pushing directly to `main`
- **MUST** sign commits (`-s -S`) and tags (`-s`, never `git tag -a`)
- **MUST NOT** add `Co-Authored-By: Claude` or `Generated with Claude Code` footers
- **MUST** update `CHANGELOG.md` and the relevant `CLAUDE.md` files when behavior or structure changes
- **MUST** format markdown with prettier
- **MUST** use `rg` and `fd` for searching

### Code

- **MUST** run `uv run ruff check` and `uv run pytest` before committing
- **MUST** type-hint all public functions; no `any` without justification
- **MUST NOT** commit secrets, credentials, or `.env*` files
- **MUST NOT** disable security checks without documenting why
- Use modern Python type syntax: `list[T]`, `dict[K, V]`, `T | None` (no `Optional`/`List`/`Dict`)

### Versioning

- Version lives only in `iam_validator/__version__.py` (line 6). `pyproject.toml` reads
  it dynamically via hatch — do not duplicate it there.
- Use `/create-version-tag` to bump and tag.

---

## Slash Commands

### Procedural

| Command               | Purpose                                  |
| --------------------- | ---------------------------------------- |
| `/create-pr`          | Stage commits and push a branch for a PR |
| `/create-version-tag` | Bump version + create signed tag         |
| `/update-changelog`   | Append entry following Common Changelog  |
| `/benchmark`          | Run performance benchmarks               |

### Reasoning skills

| Skill               | Purpose                                |
| ------------------- | -------------------------------------- |
| `/add-check`        | Scaffold a new validation check        |
| `/review`           | Code-review checklist                  |
| `/fix-issue`        | Analyze and plan a GitHub issue fix    |
| `/update-claude-md` | CLAUDE.md quality + structure guidance |

---

## Development Commands

```bash
# Setup
uv sync                          # install
uv sync --extra dev              # +dev tools
uv sync --extra mcp              # +MCP server

# Quality
uv run ruff format .
uv run ruff check --fix .
uv run mypy iam_validator/
mise run check                   # format + lint + type + test

# Testing
uv run pytest
uv run pytest -k "wildcard"
uv run pytest -m "not benchmark and not slow"   # default for fast iteration
uv run pytest --cov=iam_validator --cov-report=html

# Run the validator
uv run iam-validator validate --path policy.json
uv run iam-validator validate --path ./policies/ --config config.yaml
uv run iam-validator analyze --path policy.json   # AWS Access Analyzer

# MCP server
iam-validator-mcp                # stdio
mise run mcp:inspector           # debug
```

Test markers: `benchmark` (perf), `slow` (long), `integration` (external resources).
`asyncio_mode = "auto"` is set in `pyproject.toml`.

---

## Project Map

```
iam_validator/
├── __version__.py            # single source of truth for version
├── core/                     # validation engine — see core/CLAUDE.md
│   ├── cli.py                # CLI entry point
│   ├── check_registry.py     # PolicyCheck ABC + registry
│   ├── models.py             # IAMPolicy, Statement, ValidationIssue
│   ├── policy_loader.py      # JSON/YAML loading + auto-detect
│   ├── policy_checks.py      # validation orchestrator
│   ├── pr_commenter.py       # PR comment posting + diff filtering
│   ├── report.py             # report generation
│   ├── constants.py          # centralized HTML markers, ARN patterns, size limits
│   ├── aws_service/          # AWS Service Reference fetcher (cache: memory LRU + disk TTL)
│   ├── config/               # YAML config + sensitive_actions / condition_requirements
│   └── formatters/           # console / enhanced / json / markdown / sarif / csv / html
├── checks/                   # 22 built-in checks — see checks/CLAUDE.md
├── commands/                 # 8 CLI commands — see commands/CLAUDE.md
├── mcp/                      # MCP server (35+ tools, 15 templates) — see mcp/CLAUDE.md
├── sdk/                      # public Python API — see sdk/CLAUDE.md
└── integrations/             # GitHub PR + MS Teams — see integrations/CLAUDE.md

tests/                        # mirrors source tree — see tests/CLAUDE.md
examples/                     # custom_checks/, iam-test-policies/, configs/
docs/                         # MkDocs site — see docs/CLAUDE.md
.claude/                      # commands/, skills/, settings.json, plans/
```

### Key files

| Purpose        | File                                         |
| -------------- | -------------------------------------------- |
| CLI entry      | `iam_validator/core/cli.py`                  |
| Check ABC      | `iam_validator/core/check_registry.py`       |
| Constants      | `iam_validator/core/constants.py`            |
| SDK public API | `iam_validator/sdk/__init__.py`              |
| Config loader  | `iam_validator/core/config/config_loader.py` |
| MCP server     | `iam_validator/mcp/server.py`                |
| GitHub Action  | `action.yaml`                                |

---

## Centralized Constants (read this before adding literals)

`iam_validator/core/constants.py` is the single source of truth for cross-module
literals. Add a constant there before introducing any of these inline:

- HTML comment markers (`SUMMARY_IDENTIFIER`, `REVIEW_IDENTIFIER`,
  `IGNORED_FINDINGS_IDENTIFIER`, `ANALYZER_IDENTIFIER`, `BOT_IDENTIFIER`).
  When emitting or matching one of these for a tagged run, route through
  `scoped_marker(base, comment_tag)` (validates the tag against
  `COMMENT_TAG_PATTERN`) — never splice the suffix manually.
- Body-part markers (`ISSUE_TYPE_MARKER_FORMAT/PATTERN`, `FINDING_ID_MARKER_FORMAT`,
  `FINDING_ID_STRICT_PATTERN` for the canonical 16-char hash, `FINDING_ID_LOOSE_PATTERN`
  for legacy ids)
- ARN partitions (`ARN_PARTITION_REGEX` covers commercial, `aws-cn`, `aws-us-gov`,
  `aws-eusc`, all `aws-iso*`) — sourced by `DEFAULT_ARN_VALIDATION_PATTERN` and the
  trust-policy SAML/OIDC patterns
- AWS policy size limits (`MAX_MANAGED_POLICY_SIZE`, etc.)
- GitHub comment limits (`GITHUB_COMMENT_HARD_LIMIT = 65536`,
  `GITHUB_MAX_COMMENT_LENGTH = 65000`, `GITHUB_COMMENT_SPLIT_LIMIT = 60000`)

Tests must also import from constants — never duplicate marker strings.

---

## Adding new components

See subdirectory `CLAUDE.md`: checks → `iam_validator/checks/CLAUDE.md`,
commands → `iam_validator/commands/CLAUDE.md`, formatters / config →
`iam_validator/core/CLAUDE.md`, MCP tools/templates → `iam_validator/mcp/CLAUDE.md`.

---

## Policy Type Resolution (gotcha)

- `--policy-type` / SDK `policy_type=` kwarg, when supplied, applies to **every**
  policy (auto-detection skipped).
- When omitted: per-file resolution via `policy_types:` glob mapping →
  content auto-detect (trust / resource / identity) → default `IDENTITY_POLICY`.
- `--log-level debug` emits one
  `policy_type=… source=cli-flag|config-glob|auto-detect|default file=<basename>` line
  per policy. `config-glob` lines also include `pattern_present=true pattern_len=<n>`
  (raw glob is not logged for security).
- SCP / RCP share the identity-policy shape and still need an explicit flag or glob mapping.

---

## Git conventions

Conventional Commits (`feat:`, `fix:`, `docs:`, `refactor:`, `test:`, `chore:`).
Branches: `feature/`, `fix/<issue>-`, `docs/`.

CI workflows in `.github/workflows/`: `ci.yml` (lint/test 3.10-3.14), `release.yml`
(tag → PyPI via trusted publishing), `docs.yml`, `codeql.yml`, `scorecard.yml`.
