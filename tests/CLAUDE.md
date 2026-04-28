# Tests Module

Test layout mirrors `iam_validator/`. Extends [../CLAUDE.md](../CLAUDE.md).

`asyncio_mode = "auto"` is set in `pyproject.toml` — async tests don't need
`@pytest.mark.asyncio`.

---

## Layout

```
tests/
├── checks/                  # one file per check, plus shared conftest
│   └── conftest.py          # mock_fetcher, default_config, statement/policy fixtures
├── core/                    # core engine tests + their conftest
├── commands/
├── config/
├── integrations/            # GitHub + MS Teams (all mocked)
├── mcp/
└── sdk/
```

Naming: `iam_validator/foo/bar.py` ↔ `tests/foo/test_bar.py` (or
`test_bar_<aspect>.py` when splitting).

---

## Markers

```python
@pytest.mark.benchmark   # skip with -m "not benchmark"
@pytest.mark.slow        # skip with -m "not slow"
@pytest.mark.integration # external resources, opt-in only
```

Default fast iteration: `uv run pytest -m "not benchmark and not slow"`.

---

## Common commands

```bash
uv run pytest                                            # everything
uv run pytest tests/checks/test_wildcard_action_check.py
uv run pytest -k "wildcard"                              # name filter
uv run pytest -v --tb=long                               # debug
uv run pytest --cov=iam_validator --cov-report=html
```

---

## Mocking rules

- Never hit real AWS or GitHub APIs. Mock with `unittest.mock.AsyncMock`/`MagicMock`.
- AWS service data: use the `mock_fetcher` fixture from `tests/checks/conftest.py`.
- GitHub: see existing patterns in `tests/integrations/` — wire `_make_paginated_request`,
  `update_review_comment`, `delete_review_comment`, `create_review_with_comments`.
- HTML markers in test bodies must come from `iam_validator.core.constants` (`REVIEW_IDENTIFIER`,
  `BOT_IDENTIFIER`, `ISSUE_TYPE_MARKER_FORMAT`, `FINDING_ID_MARKER_FORMAT`).
  Building bodies via these constants keeps tests in lockstep with production.
- Finding ids in fixtures must be 16 lowercase hex chars (the canonical hash format
  enforced by `FINDING_ID_STRICT_PATTERN`).

---

## Shared fixtures

`tests/checks/conftest.py` provides:

- `mock_fetcher` — `AWSServiceFetcher` with `validate_action`, `expand_wildcard_action`,
  `fetch_service_by_name` mocked
- `default_config`, `custom_config` — `CheckConfig` with and without overrides
- Statement/policy fixtures (`allow_all_statement`, `readonly_statement`,
  `simple_policy`, …)

Add new fixtures to a `conftest.py` only if reused across multiple files; otherwise
keep them colocated.

---

## Patterns

### Check test

```python
class TestMyCheck:
    @pytest.fixture
    def check(self):
        return MyCheck()

    @pytest.fixture
    def config(self):
        return CheckConfig(check_id="my_check", enabled=True)

    async def test_detects_issue(self, check, config, mock_fetcher):
        statement = Statement(effect="Allow", action=["*"], resource=["*"])
        issues = await check.execute(statement, 0, mock_fetcher, config)
        assert len(issues) == 1
        assert issues[0].issue_type == "overly_permissive"
```

### Policy-level test

Use `check.execute_policy(policy, "test.json", mock_fetcher, config)` and pass
multi-statement `IAMPolicy` instances.

### Parametrized

Prefer `@pytest.mark.parametrize` for partition / severity / wildcard matrices —
see `tests/core/test_trust_policy_validation.py::TestTrustPolicyPartitionCoverage`.
