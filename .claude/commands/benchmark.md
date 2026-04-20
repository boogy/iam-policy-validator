---
description: Run performance benchmarks
---

Run `pytest` benchmarks for the iam-policy-validator project.

Argument: `$ARGUMENTS` (optional — check name, or `validation` for the full pipeline).

## Recipes

**All benchmarks**

```bash
uv run pytest tests/ -m benchmark -p benchmark --benchmark-enable --benchmark-only -v
```

**A specific check**

```bash
uv run pytest tests/checks/ -k "$ARGUMENTS" -m benchmark -p benchmark --benchmark-enable --benchmark-only -v
```

**Validation pipeline**

```bash
uv run pytest tests/ -k "benchmark" -m benchmark -p benchmark --benchmark-enable --benchmark-only -v
```

## Regression detection

**Save a baseline** (do this once, typically on `main`):

```bash
uv run pytest tests/ -m benchmark -p benchmark --benchmark-enable --benchmark-save=baseline --benchmark-only
```

**Compare against the saved baseline**:

```bash
uv run pytest tests/ -m benchmark -p benchmark --benchmark-enable --benchmark-compare --benchmark-only
```

Flag anything >10% slower as a regression.

## Benchmark test pattern

Tests marked with `@pytest.mark.benchmark` are included:

```python
@pytest.mark.benchmark
def test_wildcard_check_performance(benchmark, check, config, mock_fetcher):
    statement = Statement(effect="Allow", action=["*"], resource=["*"])

    async def run_check():
        return await check.execute(statement, 0, mock_fetcher, config)

    result = benchmark(lambda: asyncio.run(run_check()))
    assert len(result) == 1
```

## Examples

- `/benchmark` — run all benchmarks
- `/benchmark wildcard_action` — benchmark a single check
- `/benchmark validation` — benchmark the full validation pipeline
