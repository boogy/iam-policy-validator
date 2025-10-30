# AWS Service Definitions Backup

This directory contains scripts for downloading and managing backups of AWS service definition JSON files.

## Why Download AWS Service Definitions?

The IAM Policy Validator uses the [AWS Service Reference API](https://servicereference.us-east-1.amazonaws.com/) to:
- Validate IAM action names against actual AWS services
- Expand wildcard actions (e.g., `ec2:Describe*`) to specific actions
- Validate condition keys for each action

However, relying solely on the live API has some limitations:
- **Rate limiting/throttling**: Heavy usage can hit API rate limits
- **Network dependency**: Requires internet connectivity
- **Availability**: External API dependency

## Solution: Local Backup

The `download_aws_services.py` script downloads all AWS service definitions and saves them locally as a backup.

## Usage

### Download All AWS Services

```bash
# Using make (recommended)
make download-aws-services

# Or directly with python
uv run python scripts/download_aws_services.py

# Custom output directory
uv run python scripts/download_aws_services.py --output-dir /path/to/backup

# Limit concurrent downloads
uv run python scripts/download_aws_services.py --max-concurrent 5
```

### Output Structure

The script creates this directory structure:

```
aws_services/
├── _manifest.json        # Metadata about the download (underscore = top of directory)
├── _services.json        # List of all services (underscore = top of directory)
├── s3.json              # Individual service definitions
├── ec2.json
├── iam.json
├── lambda.json
└── ...                  # ~400+ service files
```

### Files Explained

- **_manifest.json**: Contains metadata about the download (underscore prefix sorts to top)
  ```json
  {
    "download_date": "2025-01-15T10:30:00.123456",
    "total_services": 450,
    "successful_downloads": 448,
    "failed_downloads": 2,
    "base_url": "https://servicereference.us-east-1.amazonaws.com/"
  }
  ```

- **_services.json**: List of all available AWS services (underscore prefix sorts to top)
  ```json
  [
    {
      "service": "S3",
      "url": "https://servicereference.us-east-1.amazonaws.com/s3.json"
    },
    ...
  ]
  ```

- **{service}.json**: Individual service definition with actions, resources, and conditions

## Using Local AWS Services

Once you've downloaded the AWS service definitions, you can configure the validator to use them instead of calling the AWS API.

### Configuration File Method

Add `aws_services_dir` to your config file (e.g., `default-config.yaml` or custom config):

```yaml
settings:
  # Use local AWS service files instead of API
  aws_services_dir: ./aws_services

  # Other settings...
  cache_enabled: true
  cache_ttl_hours: 168
```

Then run validation as normal:

```bash
uv run iam-validator validate --path policy.json --config your-config.yaml
```

### How It Works

When `aws_services_dir` is set:
1. ✅ **No API calls** - All service definitions loaded from local files
2. ✅ **Offline validation** - Works without internet connection
3. ✅ **Faster** - No network latency
4. ✅ **No throttling** - No rate limits to worry about

When `aws_services_dir` is NOT set (default):
- Uses AWS Service Reference API
- Results are cached locally (controlled by `cache_enabled` setting)

### Benefits

- **Offline validation**: Work without internet connectivity
- **Protection against API throttling**: Heavy usage won't hit rate limits
- **Faster validation**: No network latency for each service lookup
- **Reproducible**: Pin to specific AWS API version
- **CI/CD friendly**: No external dependencies in build pipelines

## Updating the Backup

AWS regularly adds new services and updates existing ones. To keep your backup current:

```bash
# Download fresh copies
make download-aws-services
```

**Recommended frequency**: Weekly or monthly, depending on your needs.

## Advanced Options

### Parallel Downloads

Control the number of concurrent downloads to avoid overwhelming the API:

```bash
uv run python scripts/download_aws_services.py --max-concurrent 5
```

### Custom Location

Store backups in a custom location:

```bash
uv run python scripts/download_aws_services.py --output-dir ~/aws-backups
```

## Notes

- The backup directory (`aws_services/`) is committed to the repository for offline usage
- Each service JSON file is ~10-500KB (total: ~50-100MB for all services)
- Download time: ~2-5 minutes depending on network speed and concurrency settings
- The script uses asyncio for efficient parallel downloads with rate limiting
- Files are stored in the repository so the validator can work offline without internet access
