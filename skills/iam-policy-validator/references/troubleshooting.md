# Troubleshooting

## "Command not found: iam-validator"

The package isn't installed in the current environment. Options:

```bash
uvx iam-policy-validator validate --path policy.json   # no install
uv add iam-policy-validator                            # per project
pipx install iam-policy-validator                      # user-wide
```

## AWS fetch is slow / rate-limited / offline environment

The validator fetches AWS service definitions on first use and caches them. For CI or air-gapped environments:

```bash
# Pre-download once (committed to a folder you ship with CI)
iam-validator sync-services --output-dir ./aws_services/

# Use it
iam-validator validate --path ./policies/ --aws-services-dir ./aws_services/
```

## Cache management

```bash
iam-validator cache info       # stats
iam-validator cache location   # path on disk
iam-validator cache list       # cached services
iam-validator cache clear      # wipe
iam-validator cache refresh    # re-fetch cached services
iam-validator cache prefetch   # warm common services
```

Default cache locations: `~/Library/Caches/iam-validator` (macOS), `~/.cache/iam-validator` (Linux), `%LOCALAPPDATA%\iam-validator\Cache` (Windows).

## False positives from a specific check

Prefer a per-check `ignore_patterns` over disabling the check outright. Each pattern lives **inside** the check block — not at the top level of the config:

```yaml
wildcard_resource:
  enabled: true
  ignore_patterns:
    - filepath: "^examples/" # known-vulnerable demo policies
    - sid: "^AllowReadOnly"
    - action: "^s3:Describe.*"
```

Disable a check only when it's genuinely inapplicable to the policy set (for example, `sid_uniqueness` for single-statement templates).

## Wrong `--policy-type` detected

Trust-policy files routinely trigger identity-policy checks when scanned without `--policy-type TRUST_POLICY`. Pass the flag explicitly when validating trust, resource, SCP, or RCP documents — see SKILL.md "Policy types".

## Exit code behavior

By default the validator exits non-zero on **errors** (broken JSON, AWS API failure, error-severity findings). Warnings do not fail the run. Use `--fail-on-warnings` to make warnings fail too. Check stderr when the exit code surprises you.

## Got an unexpected error or bug

Re-run with `--verbose` and file an issue at https://github.com/boogy/iam-policy-validator/issues with the output.
