"""Formatting utilities for check output messages."""

from collections.abc import Iterable


def format_list_with_backticks(
    items: Iterable[str],
    max_items: int = 0,
    separator: str = ", ",
) -> str:
    """Format a list of items with markdown backticks.

    Args:
        items: Items to format.
        max_items: Maximum items to show before truncating with ``...``.
            0 means no limit.
        separator: String used to join items.

    Returns:
        Formatted string, e.g. ``"`a`, `b`, `c`"`` or ``"`a`, `b`..."``
    """
    item_list = list(items)
    if max_items and len(item_list) > max_items:
        formatted = [f"`{item}`" for item in item_list[:max_items]]
        return separator.join(formatted) + "..."
    return separator.join(f"`{item}`" for item in item_list)
