"""Re-export of the shared IAM glob matcher.

The implementation lives in ``iam_validator.core.aws_matching`` (``core`` must never
import from ``checks``); this module keeps the historical ``checks.utils`` import
path working.
"""

from iam_validator.core.aws_matching import action_matches, compile_iam_glob, iam_glob_match

__all__ = ["action_matches", "compile_iam_glob", "iam_glob_match"]
