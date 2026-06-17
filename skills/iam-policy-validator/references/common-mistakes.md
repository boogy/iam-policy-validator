# Common agent mistakes

Mistakes that cause hallucinations, misuse, or silent failures when using `iam-validator`.

### Fabricating CLI flags

**Wrong:** passing invented flags like `--check`, `--disable-check`, `--severity`, or `--exclude`.
**Right:** confirm every flag with `iam-validator <cmd> --help` before use. The CLI will error on unknown flags.

### Scanning non-IAM files as policies

**Wrong:** feeding CloudFormation templates, Terraform `.tf` files, CDK code, or SAM templates directly to `validate`.
**Right:** the validator expects a raw IAM policy document — `{"Version":"2012-10-17","Statement":[...]}`. Extract the policy block from the IaC file first, then validate it.

### Hallucinating findings when the validator returns 0 issues

**Wrong:** inventing findings when the validator reports none.
**Right:** 0 issues means the policy is clean per the checks that ran. Report it as clean. If you suspect a check did not run, verify with `--format json` and inspect the output.

### Inventing check IDs

**Wrong:** referencing IDs like `overly_permissive`, `missing_condition`, or `no_mfa` that do not exist.
**Right:** the 22 valid check IDs are listed in [checks.md](checks.md). Real check IDs appear in `validate --format json` output under each finding's `check_id` field. Never fabricate one.

### Using GitHub flags outside PR context

**Wrong:** running `--github-comment`, `--github-review`, or `post-to-pr` in local or ad-hoc contexts.
**Right:** these flags require `GITHUB_TOKEN`, `GITHUB_REPOSITORY`, and a PR event context. Without them they fail silently or error. Use `--format json` and handle posting separately.

### Forgetting `--policy-type` for non-identity policies

**Wrong:** validating trust policies, resource policies, SCPs, or RCPs without specifying type; the validator defaults to identity policy and raises false positives.
**Right:** pass `--policy-type TRUST_POLICY` (or `RESOURCE_POLICY`, `SERVICE_CONTROL_POLICY`, `RESOURCE_CONTROL_POLICY`) explicitly, or configure `policy_types:` glob mapping in the YAML config. See [configuration.md](configuration.md).

### Posting unverified findings to PRs

**Wrong:** running `validate --github-review` directly and posting whatever comes back.
**Right:** use the two-step approach — `validate --format json` to collect findings, then `query` to verify each one (see [verification-protocol.md](verification-protocol.md)), then `post-to-pr` or JSON handoff.

### Misinterpreting exit codes

**Wrong:** treating any non-zero exit as "policy is dangerous".
**Right:** exit `0` means no error-severity findings (warnings may still exist). Non-zero means error-severity findings exist, OR `--fail-on-warnings` was set and warnings are present, OR the validator itself errored (bad path, parse failure). Always read stderr and the findings before drawing conclusions.

### Assuming the first run is instant

**Wrong:** timing out or failing CI on first run because the validator appears slow.
**Right:** the first run fetches AWS service definitions (~10-30s). Subsequent runs use disk cache. For CI, pre-warm with `iam-validator sync-services` or point `--aws-services-dir` at a pre-populated directory.
