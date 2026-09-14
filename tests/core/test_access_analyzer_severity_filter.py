"""Tests for applying `hide_severities` to Access Analyzer findings.

`hide_severities` removes a severity from the run completely — not shown, not
counted, not part of the pass/fail decision. Access Analyzer findings expose the
same severity vocabulary (`error`, `warning`, `info`) through
`AccessAnalyzerFinding.severity`, but the `analyze` command never filtered them,
so a user who hid `info` to cut noise still got every SUGGESTION finding.
"""

from iam_validator.core.access_analyzer import (
    AccessAnalyzerFinding,
    AccessAnalyzerReport,
    AccessAnalyzerResult,
    FindingType,
    filter_report_by_severity,
)


def _finding(finding_type: FindingType, code: str = "CODE") -> AccessAnalyzerFinding:
    return AccessAnalyzerFinding(
        finding_type=finding_type,
        issue_code=code,
        message=f"{code} message",
        learn_more_link="https://example.invalid",
        locations=[],
    )


def _report(*findings: AccessAnalyzerFinding, policy_file: str = "p.json") -> AccessAnalyzerReport:
    has_errors = any(f.finding_type == FindingType.ERROR for f in findings)
    result = AccessAnalyzerResult(
        policy_file=policy_file,
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


class TestFilterReportBySeverity:
    def test_no_hidden_severities_returns_report_unchanged(self):
        report = _report(_finding(FindingType.ERROR), _finding(FindingType.SUGGESTION))

        assert filter_report_by_severity(report, None) is report
        assert filter_report_by_severity(report, frozenset()) is report

    def test_hiding_info_drops_suggestions(self):
        report = _report(
            _finding(FindingType.SECURITY_WARNING, "SEC"),
            _finding(FindingType.SUGGESTION, "SUG"),
        )

        filtered = filter_report_by_severity(report, frozenset({"info"}))

        assert [f.issue_code for f in filtered.results[0].findings] == ["SEC"]
        assert filtered.total_findings == 1
        assert filtered.total_suggestions == 0
        assert filtered.total_warnings == 1

    def test_hiding_warning_drops_both_warning_types(self):
        """SECURITY_WARNING and WARNING both map to `warning`."""
        report = _report(
            _finding(FindingType.WARNING, "WARN"),
            _finding(FindingType.SECURITY_WARNING, "SEC"),
            _finding(FindingType.ERROR, "ERR"),
        )

        filtered = filter_report_by_severity(report, frozenset({"warning"}))

        assert [f.issue_code for f in filtered.results[0].findings] == ["ERR"]
        assert filtered.total_warnings == 0

    def test_hiding_error_clears_the_failure(self):
        """Hiding completely means the hidden finding no longer gates the run.

        `analyze` derives its exit code from `total_errors`, so a hidden error
        must not keep failing the build — the same semantics the check pipeline
        already has, where a hidden severity is dropped before `is_valid`.
        """
        report = _report(_finding(FindingType.ERROR, "ERR"), _finding(FindingType.WARNING, "WARN"))
        assert report.total_errors == 1
        assert report.invalid_policies == 1

        filtered = filter_report_by_severity(report, frozenset({"error"}))

        assert filtered.total_errors == 0
        assert filtered.results[0].is_valid is True
        assert filtered.valid_policies == 1
        assert filtered.invalid_policies == 0

    def test_hiding_everything_empties_the_report(self):
        report = _report(_finding(FindingType.ERROR), _finding(FindingType.WARNING), _finding(FindingType.SUGGESTION))

        filtered = filter_report_by_severity(report, frozenset({"error", "warning", "info"}))

        assert filtered.total_findings == 0
        assert filtered.policies_with_findings == 0

    def test_a_policy_that_failed_to_validate_keeps_its_error(self):
        """A hard failure is not a finding and must survive severity filtering."""
        result = AccessAnalyzerResult(
            policy_file="broken.json",
            is_valid=False,
            findings=[],
            error="boom",
        )
        report = AccessAnalyzerReport(
            total_policies=1,
            valid_policies=0,
            invalid_policies=1,
            total_findings=0,
            results=[result],
        )

        filtered = filter_report_by_severity(report, frozenset({"error"}))

        assert filtered.results[0].error == "boom"
        assert filtered.results[0].is_valid is False
        assert filtered.invalid_policies == 1

    def test_custom_check_results_are_preserved(self):
        """Custom Access Analyzer checks are pass/fail, not severity-tagged."""
        from iam_validator.core.access_analyzer import CheckResultType, CustomCheckResult

        check = CustomCheckResult(
            check_type="CHECK_NO_NEW_ACCESS",
            result=CheckResultType.FAIL,
            message="nope",
            reasons=[],
        )
        result = AccessAnalyzerResult(
            policy_file="p.json",
            is_valid=True,
            findings=[_finding(FindingType.SUGGESTION)],
            custom_checks=[check],
        )
        report = AccessAnalyzerReport(
            total_policies=1, valid_policies=1, invalid_policies=0, total_findings=1, results=[result]
        )

        filtered = filter_report_by_severity(report, frozenset({"info"}))

        assert filtered.results[0].findings == []
        assert filtered.results[0].failed_custom_checks == 1

    def test_scalar_hide_severity_is_one_severity(self):
        report = _report(_finding(FindingType.WARNING, "WARN"), _finding(FindingType.SUGGESTION, "SUG"))

        filtered = filter_report_by_severity(report, "info")

        assert [f.issue_code for f in filtered.results[0].findings] == ["WARN"]

    def test_failed_custom_check_keeps_policy_invalid_after_filtering(self):
        from iam_validator.core.access_analyzer import CheckResultType, CustomCheckResult

        result = AccessAnalyzerResult(
            policy_file="p.json",
            is_valid=False,
            findings=[_finding(FindingType.ERROR)],
            custom_checks=[
                CustomCheckResult(check_type="NoNewAccess", result=CheckResultType.FAIL, message="", reasons=[])
            ],
        )
        report = AccessAnalyzerReport(
            total_policies=1, valid_policies=0, invalid_policies=1, total_findings=1, results=[result]
        )

        filtered = filter_report_by_severity(report, frozenset({"error"}))

        assert filtered.results[0].is_valid is False
        assert filtered.invalid_policies == 1


class TestCustomCheckFailureMakesPolicyInvalid:
    def test_validate_policies_marks_failed_custom_check_invalid(self, monkeypatch):
        from unittest.mock import MagicMock

        from iam_validator.core.access_analyzer import (
            AccessAnalyzerValidator,
            CheckResultType,
            CustomCheckResult,
        )
        from iam_validator.core.access_analyzer_report import AccessAnalyzerReportFormatter

        validator = AccessAnalyzerValidator(session=MagicMock())
        monkeypatch.setattr(validator, "validate_policy", lambda _doc: [])
        monkeypatch.setattr(
            validator,
            "check_access_not_granted",
            lambda *_a, **_k: CustomCheckResult(
                check_type="AccessNotGranted", result=CheckResultType.FAIL, message="granted", reasons=[]
            ),
        )

        results = validator.validate_policies(
            [("p.json", {"Version": "2012-10-17", "Statement": []})],
            custom_checks={"access_not_granted": {"actions": ["s3:GetObject"]}},
        )
        report = validator.generate_report(results)

        assert results[0].is_valid is False
        assert report.invalid_policies == 1
        assert "Validation Passed" not in AccessAnalyzerReportFormatter().generate_markdown_report(report)
