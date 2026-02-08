---
description: Run performance benchmarks
---

You are running performance benchmarks for the iam-policy-validator project.

Given optional arguments: $ARGUMENTS

## Steps

1. **Determine what to benchmark**:

   - If no argument: Run all benchmarks
   - If check name provided: Benchmark specific check
   - If "validation": Benchmark full validation pipeline

2. **Run benchmarks**:

   **All benchmarks**:

   ```bash
   uv run pytest tests/ -m benchmark -p benchmark --benchmark-enable --benchmark-only -v
   ```

   **Specific check** (if $ARGUMENTS provided):

   ```bash
   uv run pytest tests/checks/ -k "$ARGUMENTS" -m benchmark -p benchmark --benchmark-enable --benchmark-only -v
   ```

   **Validation pipeline**:

   ```bash
   uv run pytest tests/ -k "benchmark" -m benchmark -p benchmark --benchmark-enable --benchmark-only -v
   ```

3. **Compare with baseline** (if `.benchmarks` exists):

   ```bash
   uv run pytest tests/ -m benchmark -p benchmark --benchmark-enable --benchmark-compare --benchmark-only
   ```

4. **Save new baseline**:

   ```bash
   uv run pytest tests/ -m benchmark -p benchmark --benchmark-enable --benchmark-save=baseline --benchmark-only
   ```

5. **Analyze results**:

   - Identify slowest operations
   - Compare with previous runs
   - Flag regressions (>10% slower)

6. **Provide recommendations**:
   - Optimization opportunities
   - Caching improvements
   - Async parallelization opportunities

## Example Usage

- `/benchmark` - Run all benchmarks
- `/benchmark wildcard_action` - Benchmark specific check
- `/benchmark validation` - Benchmark validation pipeline

## Benchmark Markers

Tests marked with `@pytest.mark.benchmark` are included.

Example benchmark test:

```python
@pytest.mark.benchmark
def test_wildcard_check_performance(benchmark, check, config, mock_fetcher):
    """Benchmark WildcardActionCheck performance."""
    statement = Statement(effect="Allow", action=["*"], resource=["*"])

    async def run_check():
        return await check.execute(statement, 0, mock_fetcher, config)

    result = benchmark(lambda: asyncio.run(run_check()))
    assert len(result) == 1
```

## Output

Provide:

1. Benchmark results table
2. Comparison with baseline (if available)
3. Performance regressions (if any)
4. Optimization suggestions
