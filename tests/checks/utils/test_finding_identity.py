"""Tests for finding_identity digests."""

import os
import subprocess
import sys

from iam_validator.checks.utils.finding_identity import rule_key

_SCRIPT = (
    "from iam_validator.checks.utils.finding_identity import rule_key; "
    "print(rule_key('k', {'aws:SourceArn', 'aws:SourceAccount', 'aws:SourceOrgID', 'x', 'y', 'z'}))"
)


def test_set_key_ignores_insertion_order():
    forward, backward = set(), set()
    for value in ["a", "b", "c", "d"]:
        forward.add(value)
    for value in ["d", "c", "b", "a"]:
        backward.add(value)

    assert rule_key(forward) == rule_key(backward) == rule_key(frozenset(forward))


def test_set_key_is_stable_across_hash_seeds():
    keys = {
        subprocess.run(
            [sys.executable, "-c", _SCRIPT],
            env={**os.environ, "PYTHONHASHSEED": seed},
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        for seed in ("1", "2", "3")
    }

    assert len(keys) == 1
