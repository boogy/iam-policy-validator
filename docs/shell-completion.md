# Shell Completion

The `completion` command generates shell autocompletion scripts for bash and zsh, providing intelligent tab completion for commands, options, and cached AWS service names.

## Features

- **Command completion** - Autocomplete all main commands (validate, query, analyze, etc.)
- **Subcommand completion** - Autocomplete query subcommands (action, arn, condition)
- **Option completion** - Autocomplete command options (--service, --access-level, --fmt, etc.)
- **Dynamic service completion** - Autocomplete AWS service names from your local cache
- **Value completion** - Autocomplete predefined values (access levels, formats, etc.)

## Installation

### Bash

#### Method 1: Install to completion directory

```bash
# Create completion directory if it doesn't exist
mkdir -p ~/.bash_completion.d

# Generate and save completion script
iam-validator completion bash > ~/.bash_completion.d/iam-validator

# Source in your ~/.bashrc
echo 'source ~/.bash_completion.d/iam-validator' >> ~/.bashrc

# Reload your shell
source ~/.bashrc
```

#### Method 2: Direct evaluation

```bash
# Add to ~/.bashrc for automatic loading
echo 'eval "$(iam-validator completion bash)"' >> ~/.bashrc

# Or evaluate immediately in current shell
eval "$(iam-validator completion bash)"
```

### Zsh

#### Method 1: Install to completion directory

```bash
# Create completion directory if it doesn't exist
mkdir -p ~/.zsh/completion

# Generate and save completion script
iam-validator completion zsh > ~/.zsh/completion/_iam-validator

# Add to ~/.zshrc
cat >> ~/.zshrc << 'EOF'
# Add custom completion directory
fpath=(~/.zsh/completion $fpath)

# Initialize completion system
autoload -Uz compinit && compinit
EOF

# Reload your shell
source ~/.zshrc
```

#### Method 2: Direct evaluation

```bash
# Add to ~/.zshrc for automatic loading
echo 'eval "$(iam-validator completion zsh)"' >> ~/.zshrc

# Or evaluate immediately in current shell
eval "$(iam-validator completion zsh)"
```

## Usage Examples

Once installed, tab completion works for all commands and options:

### Basic Command Completion

```bash
# Press TAB to see all commands
iam-validator <TAB>
# Shows: validate post-to-pr analyze cache download-services query completion

# Type partial command and press TAB
iam-validator qu<TAB>
# Completes to: iam-validator query
```

### Query Subcommand Completion

```bash
# Complete query subcommands
iam-validator query <TAB>
# Shows: action arn condition

# Complete with partial match
iam-validator query ac<TAB>
# Completes to: iam-validator query action
```

### Option Completion

```bash
# Complete options for query action command
iam-validator query action --<TAB>
# Shows: --service --name --access-level --resource-type --condition --fmt
```

### AWS Service Name Completion

The completion script dynamically loads AWS service names from your local cache:

```bash
# Complete service names (if you have cached services)
iam-validator query action --service <TAB>
# Shows: s3 iam ec2 lambda dynamodb ... (all cached services)

# Type partial service name
iam-validator query action --service s<TAB>
# Shows: s3 ses sns sqs ssm sts secretsmanager ...
```

### Access Level Completion

```bash
# Complete access levels
iam-validator query action --service s3 --access-level <TAB>
# Shows: read write list tagging permissions-management
```

### Format Completion

```bash
# Complete output formats
iam-validator query action --service s3 --fmt <TAB>
# Shows: json yaml text
```

## How It Works

### Cached Service Discovery

The completion script intelligently discovers cached AWS services by:

1. Reading the cache directory location from `ServiceFileStorage`
2. Scanning for cached service files (format: `{service}_{hash}.json`)
3. Extracting service names from filenames
4. Providing them as completion candidates

This means:

- **No network calls** - Only uses locally cached services
- **Fast completion** - Reads from disk cache
- **Automatic updates** - As you query new services, they become available in completion

### Example Cache Structure

```
~/.cache/iam-validator/aws_services/
├── s3_abc123.json          → service: s3
├── iam_def456.json         → service: iam
├── ec2_ghi789.json         → service: ec2
└── services_list.json      → (metadata file, ignored)
```

## Completion Behavior

### Bash Completion

- Uses `compgen` for word matching
- Provides completions based on previous argument (`$prev`)
- Handles nested subcommands (e.g., `query action`)
- Supports partial matching (e.g., `s3` matches when typing `s`)

### Zsh Completion

- Uses `_arguments` for sophisticated completion
- Provides descriptions for each option
- Supports nested completion contexts
- Shows descriptions in completion menu
- Better handling of multiple arguments

## Troubleshooting

### Completion not working

**Bash:**

```bash
# Check if completion is loaded
complete -p iam-validator

# Expected output:
# complete -F _iam_validator_completion iam-validator

# If not loaded, source it again
source ~/.bash_completion.d/iam-validator
```

**Zsh:**

```bash
# Check if completion function exists
which _iam_validator

# Rebuild completion cache
rm -f ~/.zcompdump
autoload -Uz compinit && compinit
```

### No service names in completion

Service names appear in completion only after they've been cached. To populate the cache:

```bash
# Query a few services to populate cache
iam-validator query action --service s3
iam-validator query action --service iam
iam-validator query action --service ec2

# Now service names should appear in completion
iam-validator query action --service <TAB>
```

### Completion is slow

If you have many cached services, completion might be slow. The script limits service discovery to:

- Only reading filenames (not file contents)
- Using efficient glob patterns
- Caching the service list during the completion session

If completion is still slow, you can clear old cache entries:

```bash
iam-validator cache --clear
```

## Advanced Usage

### Generating for CI/CD

You can generate completion scripts in CI/CD pipelines:

```bash
# In Dockerfile
RUN iam-validator completion bash > /etc/bash_completion.d/iam-validator

# In CI script
iam-validator completion zsh > /usr/local/share/zsh/site-functions/_iam-validator
```

### Custom Completion Locations

**Bash system-wide:**

```bash
sudo iam-validator completion bash > /etc/bash_completion.d/iam-validator
```

**Zsh system-wide:**

```bash
sudo iam-validator completion zsh > /usr/local/share/zsh/site-functions/_iam-validator
```

### Updating Completion

When you update iam-validator, regenerate the completion script:

```bash
# Bash
iam-validator completion bash > ~/.bash_completion.d/iam-validator
source ~/.bash_completion.d/iam-validator

# Zsh
iam-validator completion zsh > ~/.zsh/completion/_iam-validator
rm -f ~/.zcompdump
autoload -Uz compinit && compinit
```

## Implementation Details

The completion command is implemented as a clean, maintainable module:

- **Separation of concerns** - Bash and zsh generators are separate methods
- **Efficient caching** - Service names loaded once per completion session
- **Error handling** - Gracefully handles missing cache or permission errors
- **No external dependencies** - Uses only Python standard library

### File Organization

```
iam_validator/
└── commands/
    └── completion.py          # Completion command implementation
        ├── CompletionCommand          # Main command class
        ├── _get_cached_services()     # Service discovery
        ├── _generate_bash_completion() # Bash script generator
        └── _generate_zsh_completion()  # Zsh script generator
```

## Related Commands

- [iam-validator cache](cache-command.md) - Manage cache (affects service completion)
- [iam-validator query](query-command.md) - Query AWS services (populates cache)
- [iam-validator download-services](download-services.md) - Pre-download services
