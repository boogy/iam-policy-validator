# Core Module

Validation engine, models, AWS integration. Extends [../../CLAUDE.md](../../CLAUDE.md).

---

## Layout

```
core/
├── cli.py                  # CLI entry point (argparse + ALL_COMMANDS dispatch)
├── check_registry.py       # PolicyCheck ABC, CheckConfig, CheckRegistry, create_default_registry
├── models.py               # Pydantic v2: IAMPolicy, Statement, ValidationIssue, PolicyValidationResult
├── policy_loader.py        # JSON/YAML loading + auto-detect (also embedded in CFN/Terraform)
├── policy_checks.py        # validate_policies() orchestrator
├── report.py               # ReportGenerator, ContextIssueInfo, IgnoredFindingInfo
├── pr_commenter.py         # diff-aware PR posting (3 tiers, off-diff pipeline)
├── diff_parser.py          # git-diff parsing
├── finding_fingerprint.py  # FindingFingerprint, compute_finding_hash() (canonical 16-char)
├── label_manager.py        # severity → PR label mapping
├── access_analyzer.py      # AWS Access Analyzer client
├── access_analyzer_report.py # markdown formatter for Access Analyzer
├── ignore_patterns.py      # CODEOWNERS-driven finding suppression
├── ignore_processor.py     # ignore-command parser
├── ignored_findings.py     # storage (hidden PR comment with JSON payload)
├── codeowners.py
├── constants.py            # central markers, ARN partition regex, size limits
├── aws_service/            # service-reference fetcher (memory LRU + disk TTL 7 days)
├── config/                 # YAML config + sensitive_actions / condition_requirements
└── formatters/             # 7 output formatters
```

---

## Pipeline

```
PolicyLoader.load_*  →  validate_policies()
                          ├─ _resolve_policy_type() per file
                          │    cli-flag > config-glob > auto-detect > default
                          ├─ execute_policy_checks()       # policy-level
                          └─ execute_checks_parallel()     # statement-level, async
                        →  ignore_patterns filter
                        →  ReportGenerator.generate_report()
                        →  Formatter (console|json|markdown|sarif|csv|html)
```

`PRCommenter` then runs diff-aware filtering with 3 tiers (changed line → inline review
comment, modified statement / unchanged line → off-diff pipeline → context-issue table
in summary). `protected_fingerprints` keeps off-diff comments alive across the
`update_or_create_review_comments` cleanup phase.

---

## AWS Service Fetcher

```python
async with AWSServiceFetcher() as fetcher:                # offline: AWSServiceFetcher(aws_services_dir=...)
    is_valid, err, is_wildcard = await fetcher.validate_action("s3:GetObject")
    actions = await fetcher.expand_wildcard_action("s3:Get*")
    service = await fetcher.fetch_service_by_name("s3")    # .actions, .resources, .condition_keys
```

Two-layer cache: memory LRU (raw JSON + Pydantic models) → disk TTL (raw JSON only).
Cache dirs: `~/Library/Caches` (macOS), `~/.cache` (Linux), `%LOCALAPPDATA%` (Win).
Sub-files: `client.py` (httpx + retry + request coalescing), `cache.py`, `storage.py`,
`validators.py`, `parsers.py`, `patterns.py` (compiled regex singletons).

---

## Configuration

```python
from iam_validator.core.config.config_loader import ValidatorConfig, load_validator_config
config = load_validator_config("iam-validator.yaml")  # Priority: CLI > config > defaults
```

`config/`:

- `defaults.py` — defaults (don't hardcode `policy_type` here; see policy-size gotcha in CHANGELOG 1.19.0)
- `sensitive_actions.py` — 490+ entries by risk category
- `condition_requirements.py` — action → required conditions
- `aws_global_conditions.py` — all AWS global condition keys
- `service_principals.py`, `wildcards.py`

---

## Adding things

| Need                     | Steps                                                                                            |
| ------------------------ | ------------------------------------------------------------------------------------------------ |
| New formatter            | `formatters/my_format.py` extending `BaseFormatter`; wire into formatter selection logic         |
| New config option        | default in `config/defaults.py` → field on `ValidatorConfig` in `config/config_loader.py` → docs |
| New global condition key | `config/aws_global_conditions.py`                                                                |
| New sensitive action     | `config/sensitive_actions.py` with risk category                                                 |
