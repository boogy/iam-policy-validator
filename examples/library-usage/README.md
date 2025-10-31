# Python Library Usage Examples

This directory contains practical examples of using IAM Policy Validator as a Python library.

## Examples Overview

### Quick Reference

**[quick_reference.py](quick_reference.py)** - Copy-paste ready code snippets
- Basic validation
- Configuration loading
- Custom checks
- Filtering results
- Multiple output formats
- Batch processing
- Statistics extraction

### Basic Examples

1. **[example1_basic_usage.py](example1_basic_usage.py)** - Basic validation with default configuration
   - Simplest way to get started
   - Uses default built-in checks
   - Console output

2. **[example2_config_file.py](example2_config_file.py)** - Using a YAML configuration file
   - Load configuration from file
   - Configure checks and settings
   - Production-ready approach

3. **[example3_programmatic_config.py](example3_programmatic_config.py)** - Programmatic configuration
   - Create config in Python code
   - Dynamic configuration
   - Advanced control

## Running the Examples

### Prerequisites

```bash
# Install the package
uv add iam-policy-validator

# Or with pip
pip install iam-policy-validator
```

### Setup Test Policies

Create a test policy directory:

```bash
mkdir -p policies
cat > policies/test-policy.json << 'EOF'
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
```

### Run Examples

```bash
# Example 1: Basic usage
python example1_basic_usage.py

# Example 2: With config file (create iam-validator.yaml first)
python example2_config_file.py

# Example 3: Programmatic config
python example3_programmatic_config.py
```

## Configuration File Example

Create `iam-validator.yaml`:

```yaml
settings:
  fail_on_severity: ["error", "critical"]
  cache_enabled: true
  cache_ttl_hours: 168
  parallel_execution: true
  enable_builtin_checks: true

# Configure built-in checks
security_best_practices_check:
  enabled: true
  severity: high

action_validation_check:
  enabled: true
  severity: error
```

## Complete Documentation

For comprehensive documentation on using the library, see:
- **[Python Library Usage Guide](../../docs/python-library-usage.md)** - Complete guide with all use cases
- **[Configuration Reference](../../docs/configuration.md)** - YAML configuration options
- **[Custom Checks Guide](../../docs/custom-checks.md)** - Creating custom validation rules

## Additional Examples

For more advanced examples, see the main documentation:
- Custom checks integration
- Batch processing
- CI/CD integration
- Report generation in multiple formats
- Direct registry control
- Streaming validation
