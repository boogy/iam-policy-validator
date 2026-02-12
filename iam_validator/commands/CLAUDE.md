# Commands Module - CLI Command Development

**Purpose**: CLI commands for iam-validator tool
**Parent Context**: Extends [../../CLAUDE.md](../../CLAUDE.md)

---

## Module Overview

```
commands/
├── __init__.py          # ALL_COMMANDS list, get_command()
├── base.py              # Command abstract base class
├── validate.py          # Main validation command
├── analyze.py           # AWS Access Analyzer integration
├── post_to_pr.py        # GitHub PR comment posting
├── cache.py             # Cache management
├── download_services.py # Offline AWS service download
├── query.py             # AWS service queries
├── completion.py        # Shell completions (bash, zsh)
└── mcp.py               # MCP server launcher
```

---

## Command Base Class (`base.py`)

All commands inherit from `Command`:

```python
from abc import ABC, abstractmethod
import argparse

class Command(ABC):
    """Abstract base for CLI commands."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Command name (used in CLI)."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Command description (shown in --help)."""
        pass

    @abstractmethod
    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        """Add command-specific arguments."""
        pass

    @abstractmethod
    async def execute(self, args: argparse.Namespace) -> int:
        """Execute the command. Returns exit code (0=success)."""
        pass
```

---

## Adding a New Command

### 1. Create Command File

Create `iam_validator/commands/my_command.py`:

```python
"""My custom command."""

import argparse
from iam_validator.commands.base import Command


class MyCommand(Command):
    """One-line description of command."""

    @property
    def name(self) -> str:
        return "my-command"

    @property
    def description(self) -> str:
        return "Longer description for help text"

    def add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--path",
            required=True,
            help="Path to policy file",
        )
        parser.add_argument(
            "--verbose",
            action="store_true",
            help="Enable verbose output",
        )
        parser.add_argument(
            "--format",
            choices=["json", "console", "markdown"],
            default="console",
            help="Output format (default: console)",
        )

    async def execute(self, args: argparse.Namespace) -> int:
        """Execute the command."""
        try:
            # Your command logic here
            if args.verbose:
                print(f"Processing: {args.path}")

            # Return 0 for success, non-zero for failure
            return 0
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1
```

### 2. Register Command

Add to `iam_validator/commands/__init__.py`:

```python
from iam_validator.commands.my_command import MyCommand

ALL_COMMANDS: list[Command] = [
    ValidateCommand(),
    AnalyzeCommand(),
    # ... existing commands
    MyCommand(),  # Add here
]
```

### 3. Add Shell Completions

Update `iam_validator/commands/completion.py`:

```python
# In BASH_COMPLETION template
"my-command")
    COMPREPLY=($(compgen -W "--path --verbose --format" -- "${cur}"))
    ;;

# In ZSH_COMPLETION template
'my-command:My command description'
```

### 4. Add Tests

Create `tests/commands/test_my_command.py`:

```python
import pytest
from argparse import Namespace
from iam_validator.commands.my_command import MyCommand


class TestMyCommand:
    @pytest.fixture
    def command(self):
        return MyCommand()

    def test_name(self, command):
        assert command.name == "my-command"

    @pytest.mark.asyncio
    async def test_execute_success(self, command, tmp_path):
        # Create test policy file
        policy_file = tmp_path / "policy.json"
        policy_file.write_text('{"Version": "2012-10-17", "Statement": []}')

        args = Namespace(
            path=str(policy_file),
            verbose=False,
            format="console",
        )

        exit_code = await command.execute(args)
        assert exit_code == 0

    @pytest.mark.asyncio
    async def test_execute_missing_file(self, command):
        args = Namespace(
            path="/nonexistent/path.json",
            verbose=False,
            format="console",
        )

        exit_code = await command.execute(args)
        assert exit_code != 0
```

---

## Existing Commands Reference

### `validate` - Main Validation Command

```bash
iam-validator validate --path policy.json [options]

Options:
  --path PATH              Policy file or directory
  --config FILE            Configuration YAML file
  --format FORMAT          Output format (console|json|markdown|sarif|csv|html)
  --policy-type TYPE       Policy type (IDENTITY_POLICY|RESOURCE_POLICY|TRUST_POLICY)
  --fail-on-warnings       Exit non-zero on warnings
  --recursive              Scan directories recursively
  --include PATTERN        Include files matching pattern
  --exclude PATTERN        Exclude files matching pattern
```

### `analyze` - AWS Access Analyzer

```bash
iam-validator analyze --path policy.json [options]

Options:
  --path PATH              Policy file to analyze
  --analyzer-type TYPE     IAM, S3, etc.
  --locale LOCALE          Locale for findings
```

### `post-to-pr` - GitHub PR Comments

```bash
iam-validator post-to-pr --path policy.json --pr-number 123 [options]

Options:
  --path PATH              Policy file or directory
  --pr-number NUM          GitHub PR number
  --github-token TOKEN     GitHub API token
  --repo OWNER/REPO        Repository name
```

### `cache` - Cache Management

```bash
iam-validator cache [subcommand]

Subcommands:
  clear                    Clear the AWS service cache
  info                     Show cache statistics
```

### `query` - AWS Service Queries

```bash
iam-validator query [subcommand] [options]

Subcommands:
  actions SERVICE          List actions for a service
  action ACTION            Get action details
  arn-formats SERVICE      Get ARN formats for a service
  condition-keys SERVICE   List condition keys
```

### `completion` - Shell Completions

```bash
iam-validator completion [shell]

Shells:
  bash                     Generate bash completions
  zsh                      Generate zsh completions
```

### `mcp` - MCP Server

```bash
iam-validator mcp [options]

Options:
  --transport TYPE         Transport type (stdio|sse)
  --host HOST              Host for SSE transport
  --port PORT              Port for SSE transport
  --org-config FILE        Organization config YAML
  --verbose                Enable verbose logging
```

---

## Common Patterns

### Async Execution

Commands use async for I/O operations:

```python
async def execute(self, args: argparse.Namespace) -> int:
    async with AWSServiceFetcher() as fetcher:
        # Use fetcher for AWS operations
        result = await fetcher.validate_action("s3:GetObject")
    return 0
```

### Rich Console Output

Use Rich for formatted output:

```python
from rich.console import Console
from rich.table import Table

console = Console()

async def execute(self, args: argparse.Namespace) -> int:
    table = Table(title="Results")
    table.add_column("Policy")
    table.add_column("Issues")

    for result in results:
        table.add_row(result.policy_file, str(len(result.issues)))

    console.print(table)
    return 0
```

### Progress Indicators

```python
from rich.progress import Progress

async def execute(self, args: argparse.Namespace) -> int:
    with Progress() as progress:
        task = progress.add_task("Validating...", total=len(files))
        for file in files:
            # Process file
            progress.advance(task)
    return 0
```

### Error Handling

```python
import sys
from rich.console import Console

console = Console(stderr=True)

async def execute(self, args: argparse.Namespace) -> int:
    try:
        # Command logic
        return 0
    except FileNotFoundError as e:
        console.print(f"[red]Error:[/red] File not found: {e}")
        return 1
    except ValidationError as e:
        console.print(f"[red]Validation failed:[/red] {e}")
        return 2
```

---

## Quick Search

```bash
# Find command by name
rg -n "def name.*:" .

# Find all argument definitions
rg -n "add_argument\(" .

# Find command execution
rg -n "async def execute" .

# Find where commands are registered
rg -n "ALL_COMMANDS" __init__.py
```
