"""Terminal utilities for console output formatting."""

import shutil


def get_terminal_width(min_width: int = 80, max_width: int = 150, fallback: int = 100) -> int:
    """Get the current terminal width with reasonable bounds.

    Args:
        min_width: Minimum width to return (default: 80)
        max_width: Maximum width to return (default: 150)
        fallback: Fallback width if detection fails (default: 100)

    Returns:
        Terminal width within the specified bounds
    """
    try:
        terminal_width = shutil.get_terminal_size().columns
        # Ensure width is within reasonable bounds
        return max(min(terminal_width, max_width), min_width)
    except Exception:
        return fallback
