"""`analyze` applies `settings.hide_severities` to Access Analyzer findings.

The command never read the config file, so hidden severities leaked into its
console output, its PR comment, its job summary and its exit code.
"""

import argparse

import pytest

from iam_validator.commands.analyze import AnalyzeCommand
from iam_validator.core.access_analyzer import (
    AccessAnalyzerFinding,
    AccessAnalyzerReport,
    AccessAnalyzerResult,
    FindingType,
)


def _finding(finding_type: FindingType, code: str) -> AccessAnalyzerFinding:
    return AccessAnalyzerFinding(
        finding_type=finding_type,
        issue_code=code,
        message=f"{code} message",
        learn_more_link="https://example.invalid",
        locations=[],
    )


def _report(*findings: AccessAnalyzerFinding) -> AccessAnalyzerReport:
    has_errors = any(f.finding_type == FindingType.ERROR for f in findings)
    result = AccessAnalyzerResult(
        policy_file="policy.json",
        is_valid=not has_errors,
        findings=list(findings),
    )
    return AccessAnalyzerReport(
        total_policies=1,
        valid_policies=0 if has_errors else 1,
        invalid_policies=1 if has_errors else 0,
        total_findings=len(findings),
        results=[result],
    )


def _args(config: str | None, **overrides) -> argparse.Namespace:
    args = argparse.Namespace(
        paths=["policy.json"],
        policy_type="IDENTITY_POLICY",
        region="us-east-1",
        profile=None,
        no_recursive=True,
        format="console",
        output=None,
        github_comment=False,
        fail_on_warnings=False,
        run_all_checks=False,
        verbose=False,
        config=config,
        check_access_not_granted=None,
        check_no_new_access=None,
        check_no_public_access=None,
    )
    for key, value in overrides.items():
        setattr(args, key, value)
    return args


@pytest.fixture
def config_file(tmp_path):
    def _write(hidden: list[str]) -> str:
        path = tmp_path / "iam-validator.yaml"
        body = ", ".join(hidden)
        path.write_text(f"settings:\n  hide_severities: [{body}]\n")
        return str(path)

    return _write


class TestAnalyzeHideSeverities:
    async def test_hidden_suggestions_are_not_reported(self, monkeypatch, capsys, config_file):
        report = _report(
            _finding(FindingType.SECURITY_WARNING, "SEC"),
            _finding(FindingType.SUGGESTION, "SUG"),
        )
        monkeypatch.setattr(
            "iam_validator.commands.analyze.validate_policies_with_analyzer",
            lambda **_: report,
        )

        exit_code = await AnalyzeCommand().execute(_args(config_file(["info"])))
        out = capsys.readouterr().out

        assert exit_code == 0
        assert "SEC" in out
        assert "SUG" not in out

    async def test_hiding_error_clears_the_exit_code(self, monkeypatch, config_file):
        report = _report(_finding(FindingType.ERROR, "ERR"))
        monkeypatch.setattr(
            "iam_validator.commands.analyze.validate_policies_with_analyzer",
            lambda **_: report,
        )

        assert await AnalyzeCommand().execute(_args(None)) == 1
        assert await AnalyzeCommand().execute(_args(config_file(["error"]))) == 0

    async def test_hidden_findings_do_not_fail_on_warnings(self, monkeypatch, config_file):
        report = _report(_finding(FindingType.SUGGESTION, "SUG"))
        monkeypatch.setattr(
            "iam_validator.commands.analyze.validate_policies_with_analyzer",
            lambda **_: report,
        )

        assert await AnalyzeCommand().execute(_args(None, fail_on_warnings=True)) == 1
        assert await AnalyzeCommand().execute(_args(config_file(["info"]), fail_on_warnings=True)) == 0
