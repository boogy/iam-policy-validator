"""Case-insensitive, glob-aware matching for AWS IAM identifiers.

IAM action names are case-insensitive; ``*`` matches any run of characters and ``?``
matches exactly one.
"""

import re
from functools import lru_cache


@lru_cache(maxsize=1024)
def compile_iam_glob(pattern: str) -> re.Pattern[str]:
    """Compile an IAM glob pattern case-insensitively."""
    body = re.escape(pattern).replace(r"\*", ".*").replace(r"\?", ".")
    return re.compile(f"^{body}$", re.IGNORECASE)


def iam_glob_match(pattern: str, value: str) -> bool:
    """True if ``value`` is covered by the IAM glob ``pattern``."""
    return compile_iam_glob(pattern).match(value) is not None


def action_matches(statement_action: str, target_action: str) -> bool:
    """True if a statement's action and a target action can denote the same action.

    Either side may carry globs, so the test is bidirectional: ``s3:Get*`` covers
    ``s3:GetObject`` and ``s3:GetObject`` is covered by the requirement ``s3:Get*``.
    """
    if statement_action == "*":
        return True
    return iam_glob_match(statement_action, target_action) or iam_glob_match(target_action, statement_action)
