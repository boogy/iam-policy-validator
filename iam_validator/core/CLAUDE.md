# Core Module

Validation engine, models, AWS integration. Extends [../../CLAUDE.md](../../CLAUDE.md).

---

## Layout

```
core/
├── cli.py                  # CLI entry point (argparse + ALL_COMMANDS dispatch)
├── check_registry.py       # PolicyCheck ABC, CheckConfig, CheckRegistry, create_default_registry
│                           # a check that raises -> check_execution_error finding (settings.on_check_error)
├── models.py               # Pydantic v2: IAMPolicy, Statement, ValidationIssue, PolicyValidationResult
├── policy_loader.py        # JSON/YAML loading + auto-detect
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

Policies are validated concurrently under an `asyncio.Semaphore` bounded by
`max_concurrency` (CLI/SDK argument, else the config setting, default 10). Within a
policy, statements are gathered concurrently and unbounded; statement order is preserved
because `ignore_patterns` and PR-comment fingerprints anchor to it.

`PRCommenter` then runs diff-aware filtering with 3 tiers (changed line → inline review
comment, modified statement / unchanged line → off-diff pipeline → context-issue table
in summary). `protected_fingerprints` keeps off-diff comments alive across the
`update_or_create_review_comments` cleanup phase.

---

## Finding suppression

Gated on `settings.suppress_superseded_findings` (default true) and applied in two
places, both keyed on the superseding check's `supersedes` frozenset — a check id absent
from it is never suppressed:

- `check_registry._apply_supersedes()` — statement-level, drops findings from checks a
  matching superseding check names.
- `policy_checks` — policy-level, drops findings whose `statement_index` points at a
  statement the `full_wildcard` check suppressed, again only for ids in `supersedes`.

Both paths respect the superseding check's `applies_to_policy_types`: if it does not run
for the policy type, nothing is suppressed.

`check_registry.load_entry_point_checks(registry)` registers third-party checks advertised
under the `iam_validator.checks` entry-point group (`ENTRY_POINT_GROUP`). An entry that is
not a `PolicyCheck`, or whose `check_id` is already registered, is logged and skipped
rather than aborting discovery. It lives in `check_registry` so `create_default_registry()`
does not have to import `config_loader` — `ConfigLoader.load_entry_point_checks` remains as
a thin delegator. Patch `iam_validator.core.check_registry.entry_points` in tests.

---

## AWS Service Fetcher

```python
async with AWSServiceFetcher() as fetcher:  # offline: AWSServiceFetcher(aws_services_dir=...)
    is_valid, err, is_wildcard = await fetcher.validate_action("s3:GetObject")
    actions = await fetcher.expand_wildcard_action("s3:Get*")
    service = await fetcher.fetch_service_by_name("s3")  # .actions, .resources, .condition_keys
```

`validate_action`, `validate_actions_batch` and `validate_condition_key` return their
normal result type for an action they cannot parse (e.g. `*:Untag*`, whose service prefix
AWS rejects outright) rather than raising `ValueError` — a raise reaches
`check_registry`, which logs it and drops every finding from that check for the whole
statement. `parse_action` still raises; `describe_action_format_error` builds the message.

`validate_condition_key` accepts what the Service Reference cannot enumerate: the standard
OIDC claims (`aud`, `sub`, `oaud`, `amr`) on `sts:AssumeRoleWithWebIdentity` for any
provider URL, and keys whose provider identifier AWS templates as `${Name}`
(`token.actions.${Domain}.ghe.com:actor`). Constants live in `constants.py`.

Two-layer cache: memory LRU (raw JSON + Pydantic models) → disk TTL (raw JSON only).
Disk reads and writes run on a worker thread (`asyncio.to_thread`) so cache I/O never
blocks the event loop.
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
| Third-party check        | advertise the class under the `iam_validator.checks` entry-point group (no core edit)            |
