# Python Library Usage Examples

This directory contains practical examples of using IAM Policy Validator as a Python library in your own applications.

## Examples Overview

### Quick Start

**[quick_reference.py](quick_reference.py)** - Copy-paste ready code snippets for common operations
- Basic validation
- Configuration loading
- Custom checks integration
- Filtering results by severity
- Multiple output formats (JSON, HTML, CSV)
- Batch processing
- Statistics extraction

### Step-by-Step Examples

1. **[example1_basic_usage.py](example1_basic_usage.py)** - Basic validation with defaults
   - Simplest way to get started
   - Uses all built-in checks with default configuration
   - Console report output
   - Best for: Quick validation, CI/CD, testing

2. **[example2_config_file.py](example2_config_file.py)** - Validation with YAML configuration
   - Load configuration from YAML file
   - Enable/disable specific checks
   - Configure check severities and thresholds
   - Config auto-discovery
   - Best for: Production validation, team standards

3. **[example3_programmatic_config.py](example3_programmatic_config.py)** - Programmatic configuration
   - Create configuration dynamically in Python
   - Build custom check registries
   - Runtime configuration control
   - Direct registry API usage
   - Best for: Dynamic configs, embedded validation

4. **[example4_custom_condition_requirements.py](example4_custom_condition_requirements.py)** - Modular condition requirements
   - Use built-in condition requirement modules
   - Pick requirements by name or severity
   - Add custom inline requirements
   - Environment-specific configurations
   - Best for: Action condition enforcement customization

## Running the Examples

### Prerequisites

```bash
# Install the package
uv add iam-policy-validator

# Or with pip
pip install iam-policy-validator

# For development
git clone https://github.com/boogy/iam-policy-auditor.git
cd iam-policy-auditor
uv sync
```

### Setup Test Policies

Create a test policy directory with sample policies:

```bash
mkdir -p policies

# Create a simple S3 read policy
cat > policies/s3-read-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowS3Read",
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::my-bucket/*"
    }
  ]
}
EOF

# Create a policy with potential issues (for testing)
cat > policies/test-wildcard-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AdminAccess",
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }
  ]
}
EOF
```

### Run Examples

```bash
# Example 1: Basic usage (no config needed)
python example1_basic_usage.py

# Example 2: With config file (see Configuration section below)
python example2_config_file.py

# Example 3: Programmatic config (no config file needed)
python example3_programmatic_config.py

# Example 4: Custom condition requirements
python example4_custom_condition_requirements.py

# Quick reference (all code snippets in one file)
python quick_reference.py
```

## Configuration File Example

Create `iam-validator.yaml` in the same directory as your examples:

```yaml
# Global settings
settings:
  fail_on_severity: ["error", "critical"]
  cache_enabled: true
  cache_ttl_hours: 168  # 7 days
  parallel_execution: true
  enable_builtin_checks: true

# Built-in check configurations
wildcard_action:
  enabled: true
  severity: high

action_validation:
  enabled: true
  severity: error

principal_validation:
  enabled: true
  severity: critical
  # See docs/configuration.md for all principal validation options

wildcard_resource:
  enabled: true
  severity: medium

# Action condition enforcement
action_condition_enforcement:
  enabled: true
  severity: high
  # Uses default requirements, or customize with:
  # action_condition_requirements: [...]
```

See [examples/configs/](../configs/) for more configuration examples.

## Key Concepts

### PolicyLoader
Loads IAM policies from files or directories:
```python
from iam_validator.core.policy_loader import PolicyLoader

loader = PolicyLoader()
policies = loader.load_from_path("./policies/")  # Returns list of (file_path, policy) tuples
```

### validate_policies()
Main validation function (async):
```python
from iam_validator.core.policy_checks import validate_policies

# Basic usage (default config)
results = await validate_policies(policies)

# With config file
results = await validate_policies(
    policies,
    config_path="./iam-validator.yaml",
    use_registry=True
)
```

### ReportGenerator
Generate and output validation reports:
```python
from iam_validator.core.report import ReportGenerator

generator = ReportGenerator()
report = generator.generate_report(results)

# Console output
generator.print_console_report(report)

# Or export to file
from iam_validator.core.formatters.json import JsonFormatter
json_output = JsonFormatter().format(report)
```

### Results Structure
Each result contains:
- `policy_file`: Path to the policy file
- `is_valid`: Boolean indicating if policy passed validation
- `issues`: List of ValidationIssue objects
- Each issue has: `severity`, `message`, `suggestion`, `line_number`, etc.

## Complete Documentation

For comprehensive documentation, see:
- **[Python Library Usage Guide](../../docs/python-library-usage.md)** - Complete API reference
- **[Configuration Guide](../../docs/configuration.md)** - All configuration options
- **[Modular Configuration](../../docs/modular-configuration.md)** - Condition requirements system
- **[Custom Checks](../custom_checks/README.md)** - Create your own validation rules

## Need Help?

1. Check the [docs/](../../docs/) directory for detailed guides
2. Look at [examples/configs/](../configs/) for configuration examples
3. See [examples/custom_checks/](../custom_checks/) for custom check examples
4. Open an issue on GitHub for questions
