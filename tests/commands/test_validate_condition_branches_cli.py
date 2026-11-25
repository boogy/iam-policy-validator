"""End-to-end CLI run of an action_condition_enforcement requirement with `if:` branches."""

import json
import subprocess
import sys
from pathlib import Path

FIXTURES = Path(__file__).parent.parent / "fixtures" / "action_condition_branches"


def _validate(policy: str) -> list[dict]:
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "iam_validator",
            "validate",
            "--path",
            str(FIXTURES / policy),
            "--config",
            str(FIXTURES / "config.yaml"),
            "--format",
            "json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    report = json.loads(result.stdout)
    return [i for r in report["results"] for i in r["issues"]]


def test_noncompliant_allow_is_reported():
    issues = _validate("allow-noncompliant.json")

    assert [(i["issue_type"], i["severity"], i["condition_key"]) for i in issues] == [
        ("missing_required_condition", "critical", "bedrock:bearerTokenType")
    ]


def test_compliant_allow_is_clean():
    assert _validate("allow-compliant.json") == []
