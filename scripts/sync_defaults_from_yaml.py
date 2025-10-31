#!/usr/bin/env python3
"""
Sync defaults.py from default-config.yaml

This script updates the DEFAULT_CONFIG dictionary in defaults.py
with the configuration from default-config.yaml.

Usage:
    python scripts/sync_defaults_from_yaml.py
    make sync-defaults
"""

from pathlib import Path

import yaml


def load_yaml_config(yaml_path: Path) -> dict:
    """Load configuration from YAML file."""
    with open(yaml_path) as f:
        return yaml.safe_load(f)


def extract_config_dict_from_defaults(defaults_py_content: str) -> tuple[int, int]:
    """
    Find the start and end positions of DEFAULT_CONFIG dict in defaults.py.

    Returns:
        Tuple of (start_line, end_line) indices (0-based)
    """
    lines = defaults_py_content.split("\n")

    # Find the start of DEFAULT_CONFIG
    start_line = None
    for i, line in enumerate(lines):
        if "DEFAULT_CONFIG" in line and "=" in line and "{" in line:
            start_line = i
            break

    if start_line is None:
        raise ValueError("Could not find DEFAULT_CONFIG definition in defaults.py")

    # Find the end of DEFAULT_CONFIG (matching closing brace)
    brace_count = 0
    end_line = None
    for i in range(start_line, len(lines)):
        line = lines[i]
        brace_count += line.count("{") - line.count("}")
        if brace_count == 0 and i > start_line:
            end_line = i
            break

    if end_line is None:
        raise ValueError("Could not find end of DEFAULT_CONFIG dictionary")

    return start_line, end_line


def dict_to_python_literal(obj, indent=0, key_quotes='"'):
    """
    Convert Python dict to formatted Python code string.

    Args:
        obj: The object to convert
        indent: Current indentation level
        key_quotes: Quote style for dictionary keys ('"' or "'")

    Returns:
        Formatted Python code string
    """
    indent_str = "    " * indent
    next_indent_str = "    " * (indent + 1)

    if isinstance(obj, dict):
        if not obj:
            return "{}"

        lines = ["{"]
        for key, value in obj.items():
            value_str = dict_to_python_literal(value, indent + 1, key_quotes)
            # Handle multiline values
            if (
                "\n" in value_str
                and not value_str.strip().startswith("{")
                and not value_str.strip().startswith("[")
            ):
                lines.append(f'{next_indent_str}{key_quotes}{key}{key_quotes}: """{value}""",')
            else:
                lines.append(f"{next_indent_str}{key_quotes}{key}{key_quotes}: {value_str},")
        lines.append(f"{indent_str}}}")
        return "\n".join(lines)

    elif isinstance(obj, list):
        if not obj:
            return "[]"

        # Check if all items are simple (strings, numbers, bools)
        all_simple = all(isinstance(item, str | int | float | bool | type(None)) for item in obj)

        if all_simple and len(obj) <= 3:
            # Inline short simple lists
            items = [dict_to_python_literal(item, 0, key_quotes) for item in obj]
            return "[" + ", ".join(items) + "]"
        else:
            # Multi-line for complex or long lists
            lines = ["["]
            for item in obj:
                item_str = dict_to_python_literal(item, indent + 1, key_quotes)
                lines.append(f"{next_indent_str}{item_str},")
            lines.append(f"{indent_str}]")
            return "\n".join(lines)

    elif isinstance(obj, str):
        # Handle multiline strings
        if "\n" in obj:
            return f'"""{obj}"""'
        # Escape quotes in string
        escaped = obj.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'

    elif isinstance(obj, bool):
        return "True" if obj else "False"

    elif isinstance(obj, int | float):
        return str(obj)

    elif obj is None:
        return "None"

    else:
        return repr(obj)


def update_defaults_py(yaml_config: dict, defaults_py_path: Path):
    """Update defaults.py with configuration from YAML."""

    # Read current defaults.py
    with open(defaults_py_path) as f:
        content = f.read()

    # Find the DEFAULT_CONFIG location
    start_line, end_line = extract_config_dict_from_defaults(content)
    lines = content.split("\n")

    # Convert YAML config to Python dict literal
    python_dict_str = dict_to_python_literal(yaml_config, indent=0)

    # Create new DEFAULT_CONFIG definition
    new_config_lines = ["DEFAULT_CONFIG = " + python_dict_str]

    # Replace the old config with the new one
    new_lines = lines[:start_line] + new_config_lines + lines[end_line + 1 :]

    # Write back to file
    new_content = "\n".join(new_lines)
    with open(defaults_py_path, "w") as f:
        f.write(new_content)

    print(f"✓ Successfully updated {defaults_py_path}")
    print(f"  Replaced lines {start_line + 1}-{end_line + 1}")


def main():
    """Main entry point."""
    # Get project root
    script_dir = Path(__file__).parent
    project_root = script_dir.parent

    yaml_path = project_root / "default-config.yaml"
    defaults_py_path = project_root / "iam_validator" / "core" / "defaults.py"

    if not yaml_path.exists():
        print(f"✗ Error: {yaml_path} not found")
        return 1

    if not defaults_py_path.exists():
        print(f"✗ Error: {defaults_py_path} not found")
        return 1

    print("Syncing defaults.py from default-config.yaml...")
    print(f"  Source: {yaml_path}")
    print(f"  Target: {defaults_py_path}")
    print()

    # Load YAML config
    yaml_config = load_yaml_config(yaml_path)
    print(f"✓ Loaded YAML config ({len(yaml_config)} top-level keys)")

    # Update defaults.py
    update_defaults_py(yaml_config, defaults_py_path)

    print()
    print("✓ Sync complete!")
    print()
    print("Next steps:")
    print("  1. Review the changes: git diff iam_validator/core/defaults.py")
    print("  2. Run tests: make test")
    print("  3. Commit if everything looks good")

    return 0


if __name__ == "__main__":
    exit(main())
