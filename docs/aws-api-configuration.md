# AWS API Configuration

## Overview

The IAM Policy Validator centralizes all AWS API endpoint configuration in a single location for easier maintenance and configuration flexibility.

## Configuration Location

All AWS API endpoints are defined in:
- **Module**: [`iam_validator/core/config/aws_api.py`](../iam_validator/core/config/aws_api.py)
- **Import path**: `from iam_validator.core.config import AWS_SERVICE_REFERENCE_BASE_URL`

## Usage

### Basic Usage

```python
from iam_validator.core.config import AWS_SERVICE_REFERENCE_BASE_URL

# Use the centralized base URL
print(AWS_SERVICE_REFERENCE_BASE_URL)
# Output: https://servicereference.us-east-1.amazonaws.com/
```

### Using the Helper Function

```python
from iam_validator.core.config import get_service_reference_url

# Get URL for default region (us-east-1)
url = get_service_reference_url()

# Get URL for specific region (currently returns default for all regions)
url = get_service_reference_url("us-east-1")
```

## Files Using This Configuration

The centralized configuration is used in the following files:

1. **[`iam_validator/core/aws_fetcher.py`](../iam_validator/core/aws_fetcher.py)**
   - The main AWS service fetcher class
   - Uses `AWS_SERVICE_REFERENCE_BASE_URL` for the `BASE_URL` class attribute

2. **[`iam_validator/commands/download_services.py`](../iam_validator/commands/download_services.py)**
   - CLI command for downloading AWS service definitions
   - Uses `AWS_SERVICE_REFERENCE_BASE_URL` for fetching service data

3. **[`scripts/download_aws_services.py`](../scripts/download_aws_services.py)**
   - Standalone script for downloading service definitions
   - Uses `AWS_SERVICE_REFERENCE_BASE_URL` for fetching service data

## Benefits of Centralization

### 1. **Single Source of Truth**
- All AWS API endpoints are defined in one place
- No risk of inconsistent URLs across different files
- Easy to verify which endpoint is being used

### 2. **Easy Configuration**
- Change the endpoint once to affect all usages
- Useful for:
  - Testing with mock servers
  - Using alternative regions (when available)
  - Enterprise proxy configurations
  - Disaster recovery scenarios

### 3. **Better Maintainability**
- Clear separation of configuration from implementation
- Easier to track changes to API endpoints
- Better organization with other config modules

### 4. **Future-Proof**
- Ready for multi-region support
- Can easily add environment-based configuration
- Supports dynamic endpoint selection

## Configuration Structure

```python
# Current structure in aws_api.py

# Primary constant
AWS_SERVICE_REFERENCE_BASE_URL = "https://servicereference.us-east-1.amazonaws.com/"

# Regional endpoints map (for future expansion)
AWS_SERVICE_REFERENCE_ENDPOINTS = {
    "us-east-1": "https://servicereference.us-east-1.amazonaws.com/",
    # Add more regions as they become available
}

# Helper function
def get_service_reference_url(region: str = "us-east-1") -> str:
    """Get the AWS Service Reference API URL for a specific region."""
    return AWS_SERVICE_REFERENCE_ENDPOINTS.get(region, AWS_SERVICE_REFERENCE_BASE_URL)
```

## Migration from Old Code

### Before (Decentralized)
Each file had its own `BASE_URL` constant:

```python
# In multiple files:
BASE_URL = "https://servicereference.us-east-1.amazonaws.com/"
```

### After (Centralized)
Import from the centralized config:

```python
from iam_validator.core.config import AWS_SERVICE_REFERENCE_BASE_URL

BASE_URL = AWS_SERVICE_REFERENCE_BASE_URL
```

## Testing

The configuration is tested in [`tests/test_aws_api_config.py`](../tests/test_aws_api_config.py), which verifies:

- ✅ The constant is defined correctly
- ✅ The helper function works as expected
- ✅ The import path is accessible
- ✅ All dependent modules use the centralized config
- ✅ URL format is correct (HTTPS, trailing slash)

## Future Enhancements

Potential improvements for this configuration system:

1. **Environment Variables**: Allow override via environment variables
   ```python
   AWS_SERVICE_REFERENCE_BASE_URL = os.getenv(
       "AWS_SERVICE_REFERENCE_URL",
       "https://servicereference.us-east-1.amazonaws.com/"
   )
   ```

2. **Multi-Region Support**: Add actual regional endpoints when AWS makes them available

3. **Configuration File**: Support loading from user configuration files
   ```yaml
   aws_api:
     service_reference_url: "https://custom-endpoint.example.com/"
   ```

4. **Proxy Support**: Add proxy configuration alongside endpoint configuration

## Related Configuration Modules

Other configuration modules in `iam_validator/core/config/`:

- [`defaults.py`](../iam_validator/core/config/defaults.py) - Default check configurations
- [`sensitive_actions.py`](../iam_validator/core/config/sensitive_actions.py) - Sensitive action definitions
- [`condition_requirements.py`](../iam_validator/core/config/condition_requirements.py) - Condition requirement rules
- [`service_principals.py`](../iam_validator/core/config/service_principals.py) - Service principal definitions
- [`wildcards.py`](../iam_validator/core/config/wildcards.py) - Wildcard configurations
