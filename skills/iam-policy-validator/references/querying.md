# Querying the AWS service catalog

`iam-validator query` answers AWS IAM metadata questions without a policy file: which actions exist, which ARN formats a resource type uses, which condition keys a service exposes, and **which actions support a given condition key**. Use it to author least-privilege policies and to _verify_ validation findings before acting on them.

Three subcommands: `action`, `arn`, `condition`. All accept `--output json|yaml|text` (default `text`); use `--output json` when you need to parse the result.

> Always confirm a flag with `iam-validator query <sub> --help` before relying on it.

## query action

Flags: `--service <prefix>`, `--name <name|pattern>` (service prefix optional; supports wildcards), `--access-level read|write|list|tagging|permissions-management`, `--resource-type <type>` (`*` = wildcard-only actions), `--has-condition-key <key>` (alias `--condition`), `--show-condition-keys`, `--show-resource-types`, `--show-access-level`, `--output`.

```bash
# Every action in a service
iam-validator query action --service s3

# A single action (prefix optional)
iam-validator query action --name s3:GetObject
iam-validator query action --service s3 --name GetObject

# Expand a wildcard pattern to concrete actions
iam-validator query action --name "s3:Get*"

# Filter by access level (e.g. all write actions)
iam-validator query action --service s3 --access-level write

# Filter by resource type; "*" finds actions that only allow Resource "*"
iam-validator query action --service s3 --resource-type "*"

# Show each action's access level / supported condition keys
iam-validator query action --service s3 --name "Get*" --show-access-level --show-condition-keys
```

## query arn

Flags: `--service <prefix>`, `--name <resource-type>` (e.g. `bucket` or `s3:bucket`), `--list-arn-types`, `--has-condition-key <key>`, `--show-condition-keys`, `--show-arn-format`, `--show-resource-type`, `--output`.

```bash
# All ARN formats for a service's resource types
iam-validator query arn --service s3

# One resource type's ARN format
iam-validator query arn --service s3 --name bucket

# List all ARN types with their format templates
iam-validator query arn --service s3 --list-arn-types

# ARN resource types that support a given condition key
iam-validator query arn --service s3 --has-condition-key "s3:ResourceAccount"
```

## query condition

Flags: `--service <prefix>`, `--name <key>` (e.g. `prefix` or `s3:prefix`), `--output`.

```bash
# All condition keys a service exposes
iam-validator query condition --service s3

# Detail for one condition key
iam-validator query condition --service s3 --name "s3:prefix"
```

## Which action supports which condition (the intersection)

This is the highest-value query for scoping policies. `--has-condition-key` filters actions/ARNs down to those that accept a given key; `--show-condition-keys` lists every key an action supports.

```bash
# All actions in a service that support a condition key
iam-validator query action --service s3 --has-condition-key "s3:ResourceAccount"

# Narrow to a pattern
iam-validator query action --name "s3:Get*" --has-condition-key "s3:ResourceAccount"

# Use a global key across a service
iam-validator query action --service ec2 --has-condition-key "aws:SourceVpc"

# Machine-readable, for scripting another agent
iam-validator query action --service s3 --has-condition-key "s3:ResourceAccount" --output json
```

Condition keys are either **service-scoped** (`s3:ResourceAccount`, `kms:ViaService`) or **global** (`aws:SourceVpc`, `aws:PrincipalOrgID`, `aws:SourceArn`). Both work with `--has-condition-key`. A key that a target action does not support cannot constrain it — verify support before recommending a condition.

## Using queries to verify a finding

Before acting on a validation issue, confirm its premises with `query`:

- **"Action does not exist"** → `iam-validator query action --name <svc:Action>`. Empty/none result corroborates the finding.
- **"Add condition X"** → `iam-validator query action --name <svc:Action> --has-condition-key <X>`. If the action is absent from the result, X cannot apply — the suggestion is wrong for that action.
- **"Resource ARN is malformed"** → `iam-validator query arn --service <svc> --name <resource-type>` to get the canonical format template.
- **Wildcard scope** → `iam-validator query action --name "<svc:Prefix*>"` to see exactly which actions a wildcard expands to.

Record the query you ran and its result alongside the finding when handing off for PR review (see [pr-review-handoff.md](pr-review-handoff.md)).
