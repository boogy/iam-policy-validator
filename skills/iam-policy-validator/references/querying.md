# Querying the AWS service catalog

`iam-validator query` answers AWS IAM metadata questions without a policy file: which actions exist, which ARN formats a resource type uses, which condition keys a service exposes, and **which actions support a given condition key**. Use it to author least-privilege policies and to _verify_ validation findings before acting on them.

Four subcommands: `action`, `arn`, `condition`, `global-condition`. All accept `--output json|yaml|text` (default `json`); use `--output text` for a plain list of names.

> Always confirm a flag with `iam-validator query <sub> --help` before relying on it. `iam-validator query examples [action|arn|condition|global-condition]` (or `query --examples`) prints worked examples.

## query action

Flags: `--service <prefix>`, `--name <name|pattern> [...]` (service prefix optional; supports wildcards and several names), `--access-level read|write|list|tagging|permissions-management`, `--resource-type <type>` (`*` = wildcard-only actions), `--has-condition-key <key>` (alias `--condition`), `--data-plane` / `--control-plane`, `--show-condition-keys`, `--show-resource-types`, `--show-access-level`, `--show-data-plane`, `--show-service-name`, `--output`.

The filters (`--access-level`, `--resource-type`, `--has-condition-key`, `--data-plane`/`--control-plane`) apply to `--name` and wildcard queries as well as the list-all path. The `action` field is always `service:Action` (e.g. `s3:GetObject`). `description` appears only when AWS provides one.

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

# Data-plane (object/data access) vs control-plane (configuration) actions
iam-validator query action --service s3 --data-plane --access-level write --output text
iam-validator query action --name s3:GetObject --show-data-plane
```

`--data-plane` / `--control-plane` use AWS's `IsDataPlane` annotation. It is independent of access level (S3 data-plane actions span all five levels). `--control-plane` excludes actions AWS has not classified.

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

Flags: `--service <prefix>`, `--name <key>` (e.g. `prefix` or `s3:prefix`), `--show-types`, `--output`.

```bash
# All condition keys a service exposes
iam-validator query condition --service s3

# Detail for one condition key
iam-validator query condition --service s3 --name "s3:prefix"

# Only the value types (String, ARN, Bool, ...)
iam-validator query condition --name s3:prefix --show-types
```

## query global-condition

Global keys (`aws:*`, plus a few such as `ec2:RoleDelivery`) come from AWS's published global-condition-key list, not from any one service.

Flags: `--name <key|pattern>`, `--type <String|ArrayOfString|Bool|ARN|Date|Numeric|IPAddress>`, `--show-types`, `--show-description`, `--show-doc-url`, `--output`.

```bash
# All global condition keys
iam-validator query global-condition --output text

# One key, with types, description, and AWS docs link
iam-validator query global-condition --name aws:SourceIp

# Tag keys resolve with or without the template suffix
iam-validator query global-condition --name aws:ResourceTag   # -> aws:ResourceTag/${TagKey}

# Wildcards (case-insensitive; quote them in the shell)
iam-validator query global-condition --name 'aws:Re*' --show-types

# Keys of one type
iam-validator query global-condition --type Bool --output text
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

Condition keys are either **service-scoped** (`s3:ResourceAccount`, `kms:ViaService`) or **global** (`aws:SourceVpc`, `aws:PrincipalOrgID`, `aws:SourceArn`). Both work with `--has-condition-key`. Use `query global-condition` to confirm a global key exists and check its type. A key that a target action does not support cannot constrain it — verify support before recommending a condition.

## Using queries to verify a finding

Before acting on a validation issue, confirm its premises with `query`. The full verification checklist (8 steps) is in [verification-protocol.md](verification-protocol.md). Quick examples:

- **"Action does not exist"** → `iam-validator query action --name <svc:Action>`
- **"Add condition X"** → `iam-validator query action --name <svc:Action> --has-condition-key <X>`
- **"Resource ARN is malformed"** → `iam-validator query arn --service <svc> --name <resource-type>`
- **Condition operator / type mismatch** → `iam-validator query global-condition --name <aws:Key> --show-types` or `iam-validator query condition --name <svc:key> --show-types`
- **Wildcard scope** → `iam-validator query action --name "<svc:Prefix*>"`
