# Smart IAM Policy Filtering

The IAM Policy Validator includes intelligent file filtering that automatically detects and validates only IAM policies, skipping other JSON/YAML files like configuration files, data files, and API schemas.

## How It Works

### Automatic Detection

The validator checks each JSON/YAML file for IAM policy structure:

**IAM Policy Markers (Required):**
- `Version` field - AWS IAM policy version (usually "2012-10-17")
- `Statement` field - Array of permission statements

**Supported Formats:**
- JSON: `"Version"` and `"Statement"`
- YAML: `Version:` and `Statement:`

### What Gets Filtered Out

Files **automatically skipped** (not IAM policies):
- ❌ Application configs (`package.json`, `tsconfig.json`, `app-config.yaml`)
- ❌ Database configs (`database.json`, `db-config.yaml`)
- ❌ Data files (`users.json`, `products.json`, `inventory.yaml`)
- ❌ API schemas (`openapi.yaml`, `swagger.json`, `graphql-schema.json`)
- ❌ Build configs (`.eslintrc.json`, `jest.config.json`)
- ❌ Other JSON/YAML without IAM structure

### Example Output

When scanning a mixed directory:

```
📊 File Analysis Summary:
  Total files found: 25
  IAM policies detected: 12
  Non-IAM files skipped: 13

⏭️  Skipped non-IAM files:
  /workspace/configs/database.json
  /workspace/configs/app-settings.json
  /workspace/data/users.json
  /workspace/schemas/api-schema.json
  ... and 9 more

📋 Validating 12 IAM policies...
```

## Use Cases

### 1. Validate Changed Files in PR ⭐ **RECOMMENDED**

Only validate IAM policies that changed, automatically filtering out other files:

```yaml
name: Validate Changed IAM Policies

on:
  pull_request:
    paths:
      - '**/*.json'
      - '**/*.yaml'
      - '**/*.yml'

jobs:
  validate-changed:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write

    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Get changed JSON/YAML files
        id: changed-files
        uses: tj-actions/changed-files@v45
        with:
          files: |
            **/*.json
            **/*.yaml
            **/*.yml

      - name: Validate IAM Policies from Changed Files
        if: steps.changed-files.outputs.any_changed == 'true'
        uses: boogy/iam-policy-validator@v1
        with:
          # Automatically filters to only IAM policies
          path: ${{ steps.changed-files.outputs.all_changed_files }}
          post-comment: true
          create-review: true
          fail-on-warnings: true
```

**Benefits:**
- ✅ Only processes changed files (faster)
- ✅ Automatically filters IAM policies
- ✅ Skips configs, data files, schemas
- ✅ No false positives from non-IAM files

### 2. Scan Entire Repository

Point at any directory with mixed JSON/YAML files:

```yaml
- name: Validate All IAM Policies
  uses: boogy/iam-policy-validator@v1
  with:
    path: |
      configs/
      policies/
      infrastructure/
      data/
    # Action scans all directories and filters to IAM policies only
```

**Result:**
```
📊 Scanned directories: 4
📋 Found 156 JSON/YAML files
✅ Detected 23 IAM policies
⏭️  Skipped 133 non-IAM files
```

### 3. Mixed Repository Structure

Common in repositories with various file types:

```
repo/
├── iam-policies/         # IAM policies ✅
│   ├── lambda-role.json
│   └── s3-policy.yaml
├── terraform/
│   ├── main.tf
│   └── iam.tf           # Contains IAM policies in HCL ❌ (not JSON/YAML)
├── configs/             # Application configs ❌
│   ├── database.json
│   ├── app.yaml
│   └── secrets.json
├── data/                # Data files ❌
│   ├── users.json
│   └── products.yaml
└── schemas/             # API schemas ❌
    └── openapi.yaml
```

```yaml
- name: Validate IAM Policies
  uses: boogy/iam-policy-validator@v1
  with:
    path: .  # Scans entire repo
    # Automatically finds and validates only:
    # - iam-policies/lambda-role.json ✅
    # - iam-policies/s3-policy.yaml ✅
    # Skips all configs, data, schemas ⏭️
```

## Detection Logic

### IAM Policy Structure

A file is recognized as an IAM policy if it contains:

**JSON Format:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "*"
    }
  ]
}
```

**YAML Format:**
```yaml
Version: "2012-10-17"
Statement:
  - Effect: Allow
    Action: s3:GetObject
    Resource: "*"
```

### Non-IAM Files

Examples of files that are **automatically skipped**:

**Application Config (skipped):**
```json
{
  "database": "postgresql",
  "port": 5432,
  "credentials": {
    "username": "admin"
  }
}
```

**Data File (skipped):**
```json
{
  "users": [
    {"id": 1, "name": "Alice"},
    {"id": 2, "name": "Bob"}
  ]
}
```

**API Schema (skipped):**
```yaml
openapi: 3.0.0
info:
  title: My API
paths:
  /users:
    get:
      responses:
        200:
          description: OK
```

## Performance Benefits

### 1. Faster Validation
- No time wasted validating non-IAM files
- Early exit if no IAM policies found
- Efficient grep-based detection

### 2. Cleaner Output
- Only shows relevant IAM policy issues
- No confusing errors from non-IAM files
- Clear summary of what was processed

### 3. Better CI/CD Experience
```
✅ Fast: Only validates changed IAM policies
✅ Smart: Filters out configs, data, schemas automatically
✅ Clear: Shows exactly what was validated vs skipped
```

## Manual Control (If Needed)

If you want to validate specific files without auto-filtering:

```yaml
- name: Validate Specific Policy
  uses: boogy/iam-policy-validator@v1
  with:
    path: policies/specific-policy.json
    # Single file - filtered if not IAM policy
```

Or use the CLI directly for more control:

```bash
# CLI validates all provided files (no auto-filtering)
iam-validator validate --path specific-file.json
```

## Example Scenarios

### Scenario 1: Monorepo with Multiple Services

```
monorepo/
├── service-a/
│   ├── iam-policies/     # IAM policies ✅
│   └── configs/          # Service configs ❌
├── service-b/
│   ├── iam-policies/     # IAM policies ✅
│   └── configs/          # Service configs ❌
└── shared/
    ├── iam-policies/     # IAM policies ✅
    └── schemas/          # API schemas ❌
```

```yaml
- name: Validate All IAM Policies
  uses: boogy/iam-policy-validator@v1
  with:
    path: .
    # Finds IAM policies across all services
    # Skips all configs and schemas
```

### Scenario 2: Infrastructure as Code

```
infrastructure/
├── terraform/
│   ├── iam.tf
│   └── iam-policies.json    # IAM policy ✅
├── cloudformation/
│   └── iam-role.yaml        # IAM policy ✅
└── configs/
    └── aws-config.json      # AWS config ❌
```

```yaml
- name: Validate IaC IAM Policies
  uses: boogy/iam-policy-validator@v1
  with:
    path: infrastructure/
    # Validates: iam-policies.json, iam-role.yaml
    # Skips: aws-config.json
```

### Scenario 3: PR with Mixed Changes

```
Pull Request Changes:
  ✏️  policies/lambda-role.json        (IAM policy)
  ✏️  configs/database.json            (config file)
  ✏️  data/users.json                  (data file)
  ✏️  policies/s3-bucket-policy.yaml   (IAM policy)
```

```yaml
- name: Validate Changed IAM Policies
  uses: boogy/iam-policy-validator@v1
  with:
    path: ${{ steps.changed-files.outputs.all_changed_files }}
    # Validates: lambda-role.json, s3-bucket-policy.yaml
    # Skips: database.json, users.json
```

**Output:**
```
📊 File Analysis Summary:
  Total files found: 4
  IAM policies detected: 2
  Non-IAM files skipped: 2

⏭️  Skipped non-IAM files:
  configs/database.json
  data/users.json

✅ Validated 2 IAM policies
```

## Troubleshooting

### File Not Detected as IAM Policy

If an IAM policy isn't being detected:

1. **Check file has both required fields:**
   ```json
   {
     "Version": "2012-10-17",  // Required
     "Statement": [...]         // Required
   }
   ```

2. **Check file extension:**
   - Must be `.json`, `.yaml`, or `.yml`

3. **Check file format:**
   - JSON must have `"Version"` and `"Statement"` with quotes
   - YAML must have `Version:` and `Statement:` with colons

### False Positives

If a non-IAM file is being validated:

1. **Check if it has IAM structure:**
   - If file has both `Version` and `Statement` fields, it will be treated as IAM policy
   - Rename fields or use different file format if not an IAM policy

## Additional Resources

- **[Example Workflow](../examples/github-actions/validate-changed-files.yaml)** - Complete working example
- **[GitHub Actions README](../examples/github-actions/README.md)** - All workflow examples
- **[Configuration Guide](configuration.md)** - Advanced configuration options
