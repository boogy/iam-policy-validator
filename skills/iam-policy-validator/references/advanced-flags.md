# Advanced flags

> Always confirm a flag with `iam-validator <command> --help` before relying on it.

## `--stdin`

Read policy JSON from stdin instead of a file. Mutually exclusive with `--path`.

```bash
cat policy.json | iam-validator validate --stdin
echo '{"Version":"2012-10-17","Statement":[...]}' | iam-validator validate --stdin

# Combine with --format json for machine-readable output
cat policy.json | iam-validator validate --stdin --format json
```

## `--custom-checks-dir`

Load additional checks from a directory. Custom checks must implement the `PolicyCheck` ABC.

```bash
iam-validator validate --path ./policies/ --custom-checks-dir ./my-checks/
```

See `examples/custom_checks/` in the repo for a working implementation template.

## `--stream` and `--batch-size`

`--stream` processes files one-by-one instead of loading all into memory. Use for large policy directories or when you need progressive feedback.

`--batch-size N` sets policies per batch (default: `10`). Only meaningful with `--stream`.

```bash
iam-validator validate --path ./large-dir/ --stream
iam-validator validate --path ./large-dir/ --stream --batch-size 5
```

## `--no-recursive`

Skip subdirectories when `--path` is a directory. Default behavior is recursive.

```bash
# Validate only top-level files in ./policies/
iam-validator validate --path ./policies/ --no-recursive
```

## `--summary` and `--severity-breakdown`

Both flags only affect `--format enhanced` output.

- `--summary` adds an Executive Summary section.
- `--severity-breakdown` adds an Issue Severity Breakdown section.

```bash
iam-validator validate --path ./policies/ --format enhanced --summary --severity-breakdown
```

## `--log-level`

Global flag (place before the subcommand). Controls log verbosity.

```
--log-level {debug,info,warning,error,critical}   default: warning
```

`debug` emits one `policy_type=... source=... file=...` line per policy — useful for diagnosing auto-detection or config-glob resolution.

```bash
iam-validator --log-level debug validate --path ./policies/
```

## `completion`

Generates shell completion scripts. Helps with flag discovery during interactive use.

```bash
# bash
iam-validator completion bash > ~/.bash_completion.d/iam-validator
source ~/.bash_completion.d/iam-validator

# zsh
iam-validator completion zsh > ~/.zfunc/_iam-validator
# then add fpath=(~/.zfunc $fpath) + autoload -Uz compinit && compinit to ~/.zshrc
```
