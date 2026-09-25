"""Tests for SDK shortcut functions."""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from iam_validator.core.models import PolicyValidationResult, ValidationIssue
from iam_validator.sdk.shortcuts import (
    count_issues_by_severity,
    get_issues,
    quick_validate,
    validate_directory,
    validate_file,
    validate_json,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_result(is_valid=True, issues=None, policy_file="test.json"):
    return PolicyValidationResult(
        policy_file=policy_file,
        is_valid=is_valid,
        issues=issues or [],
    )


def _make_issue(severity="medium", message="test issue"):
    return ValidationIssue(
        severity=severity,
        statement_index=0,
        issue_type="test",
        message=message,
    )


# ---------------------------------------------------------------------------
# validate_file
# ---------------------------------------------------------------------------


class TestValidateFile:
    """Tests for validate_file()."""

    async def test_returns_result(self, tmp_policy_file):
        with patch(
            "iam_validator.sdk.shortcuts.validate_policies",
            new_callable=AsyncMock,
            return_value=[_make_result(is_valid=True, policy_file=str(tmp_policy_file))],
        ):
            result = await validate_file(tmp_policy_file)
            assert isinstance(result, PolicyValidationResult)
            assert result.is_valid is True

    async def test_accepts_string_path(self, tmp_policy_file):
        with patch(
            "iam_validator.sdk.shortcuts.validate_policies",
            new_callable=AsyncMock,
            return_value=[_make_result()],
        ):
            result = await validate_file(str(tmp_policy_file))
            assert isinstance(result, PolicyValidationResult)

    async def test_no_policies_raises(self, tmp_path):
        # A text file is not a valid policy and won't be loaded
        non_policy_file = tmp_path / "readme.txt"
        non_policy_file.write_text("this is not a policy")
        with pytest.raises((ValueError, Exception)):
            await validate_file(non_policy_file)

    async def test_with_config_path(self, tmp_policy_file):
        with patch(
            "iam_validator.sdk.shortcuts.validate_policies",
            new_callable=AsyncMock,
            return_value=[_make_result()],
        ) as mock_validate:
            await validate_file(tmp_policy_file, config_path="/tmp/config.yaml")
            _, kwargs = mock_validate.call_args
            assert kwargs["config_path"] == "/tmp/config.yaml"


# ---------------------------------------------------------------------------
# validate_directory
# ---------------------------------------------------------------------------


class TestValidateDirectory:
    """Tests for validate_directory()."""

    async def test_returns_list(self, tmp_policy_dir):
        with patch(
            "iam_validator.sdk.shortcuts.validate_policies",
            new_callable=AsyncMock,
            return_value=[_make_result(policy_file="p1.json"), _make_result(policy_file="p2.json")],
        ):
            results = await validate_directory(tmp_policy_dir)
            assert isinstance(results, list)
            assert len(results) == 2

    async def test_no_policies_raises(self, tmp_path):
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        with pytest.raises(ValueError, match="No IAM policies found"):
            await validate_directory(empty_dir)


# ---------------------------------------------------------------------------
# validate_json
# ---------------------------------------------------------------------------


class TestValidateJson:
    """Tests for validate_json()."""

    async def test_valid_policy(self, valid_policy_dict):
        with patch(
            "iam_validator.sdk.shortcuts.validate_policies",
            new_callable=AsyncMock,
            return_value=[_make_result(is_valid=True)],
        ):
            result = await validate_json(valid_policy_dict)
            assert result.is_valid is True

    async def test_custom_policy_name(self, valid_policy_dict):
        with patch(
            "iam_validator.sdk.shortcuts.validate_policies",
            new_callable=AsyncMock,
            return_value=[_make_result(policy_file="custom-name")],
        ):
            result = await validate_json(valid_policy_dict, policy_name="custom-name")
            assert result.policy_file == "custom-name"


# ---------------------------------------------------------------------------
# quick_validate
# ---------------------------------------------------------------------------


class TestQuickValidate:
    """Tests for quick_validate()."""

    async def test_dict_input_valid(self, valid_policy_dict):
        with patch(
            "iam_validator.sdk.shortcuts.validate_json",
            new_callable=AsyncMock,
            return_value=_make_result(is_valid=True),
        ):
            assert await quick_validate(valid_policy_dict) is True

    async def test_dict_input_invalid(self, wildcard_policy_dict):
        with patch(
            "iam_validator.sdk.shortcuts.validate_json",
            new_callable=AsyncMock,
            return_value=_make_result(is_valid=False),
        ):
            assert await quick_validate(wildcard_policy_dict) is False

    async def test_file_path(self, tmp_policy_file):
        with patch(
            "iam_validator.sdk.shortcuts.validate_file",
            new_callable=AsyncMock,
            return_value=_make_result(is_valid=True),
        ):
            assert await quick_validate(str(tmp_policy_file)) is True

    async def test_directory_path(self, tmp_policy_dir):
        with patch(
            "iam_validator.sdk.shortcuts.validate_directory",
            new_callable=AsyncMock,
            return_value=[_make_result(is_valid=True), _make_result(is_valid=True)],
        ):
            assert await quick_validate(str(tmp_policy_dir)) is True

    async def test_directory_path_one_invalid(self, tmp_policy_dir):
        with patch(
            "iam_validator.sdk.shortcuts.validate_directory",
            new_callable=AsyncMock,
            return_value=[_make_result(is_valid=True), _make_result(is_valid=False)],
        ):
            assert await quick_validate(str(tmp_policy_dir)) is False

    async def test_nonexistent_path_raises(self):
        with pytest.raises(FileNotFoundError, match="does not exist"):
            await quick_validate("/nonexistent/path/policy.json")

    async def test_path_object(self, tmp_policy_file):
        with patch(
            "iam_validator.sdk.shortcuts.validate_file",
            new_callable=AsyncMock,
            return_value=_make_result(is_valid=True),
        ):
            assert await quick_validate(Path(tmp_policy_file)) is True


# ---------------------------------------------------------------------------
# get_issues
# ---------------------------------------------------------------------------


class TestGetIssues:
    """Tests for get_issues()."""

    async def test_returns_issues(self, valid_policy_dict):
        issues = [_make_issue("high"), _make_issue("medium"), _make_issue("low")]
        with patch(
            "iam_validator.sdk.shortcuts.validate_json",
            new_callable=AsyncMock,
            return_value=_make_result(is_valid=False, issues=issues),
        ):
            result = await get_issues(valid_policy_dict, min_severity="low")
            assert len(result) == 3

    async def test_severity_filtering_medium(self, valid_policy_dict):
        issues = [_make_issue("high"), _make_issue("medium"), _make_issue("low")]
        with patch(
            "iam_validator.sdk.shortcuts.validate_json",
            new_callable=AsyncMock,
            return_value=_make_result(is_valid=False, issues=issues),
        ):
            result = await get_issues(valid_policy_dict, min_severity="medium")
            # high (4) >= medium (3) and medium (3) >= medium (3) — both pass
            assert len(result) == 2
            severities = {i.severity for i in result}
            assert "low" not in severities

    async def test_severity_filtering_high(self, valid_policy_dict):
        issues = [_make_issue("critical"), _make_issue("high"), _make_issue("medium")]
        with patch(
            "iam_validator.sdk.shortcuts.validate_json",
            new_callable=AsyncMock,
            return_value=_make_result(is_valid=False, issues=issues),
        ):
            result = await get_issues(valid_policy_dict, min_severity="high")
            assert len(result) == 2

    async def test_file_path_input(self, tmp_policy_file):
        with patch(
            "iam_validator.sdk.shortcuts.validate_file",
            new_callable=AsyncMock,
            return_value=_make_result(is_valid=True, issues=[]),
        ):
            result = await get_issues(str(tmp_policy_file))
            assert result == []

    async def test_directory_path_input(self, tmp_policy_dir):
        with patch(
            "iam_validator.sdk.shortcuts.validate_directory",
            new_callable=AsyncMock,
            return_value=[
                _make_result(issues=[_make_issue("high")]),
                _make_result(issues=[_make_issue("low")]),
            ],
        ):
            result = await get_issues(str(tmp_policy_dir), min_severity="high")
            assert len(result) == 1

    async def test_warning_treated_as_medium(self, valid_policy_dict):
        issues = [_make_issue("warning")]
        with patch(
            "iam_validator.sdk.shortcuts.validate_json",
            new_callable=AsyncMock,
            return_value=_make_result(is_valid=False, issues=issues),
        ):
            result = await get_issues(valid_policy_dict, min_severity="medium")
            assert len(result) == 1

    async def test_error_treated_as_high(self, valid_policy_dict):
        issues = [_make_issue("error")]
        with patch(
            "iam_validator.sdk.shortcuts.validate_json",
            new_callable=AsyncMock,
            return_value=_make_result(is_valid=False, issues=issues),
        ):
            result = await get_issues(valid_policy_dict, min_severity="high")
            assert len(result) == 1


# ---------------------------------------------------------------------------
# count_issues_by_severity
# ---------------------------------------------------------------------------


class TestCountIssuesBySeverity:
    """Tests for count_issues_by_severity()."""

    async def test_counts_by_severity(self, valid_policy_dict):
        issues = [
            _make_issue("critical"),
            _make_issue("high"),
            _make_issue("high"),
            _make_issue("medium"),
        ]
        with patch(
            "iam_validator.sdk.shortcuts.validate_json",
            new_callable=AsyncMock,
            return_value=_make_result(is_valid=False, issues=issues),
        ):
            counts = await count_issues_by_severity(valid_policy_dict)
            assert counts["critical"] == 1
            assert counts["high"] == 2
            assert counts["medium"] == 1
            assert counts.get("low", 0) == 0

    async def test_empty_issues(self, valid_policy_dict):
        with patch(
            "iam_validator.sdk.shortcuts.validate_json",
            new_callable=AsyncMock,
            return_value=_make_result(is_valid=True, issues=[]),
        ):
            counts = await count_issues_by_severity(valid_policy_dict)
            assert counts == {}


# ---------------------------------------------------------------------------
# CLI parity
# ---------------------------------------------------------------------------


def _patched_fetcher(mock_fetcher):
    """Patch the fetcher validate_policies opens so no real AWS call is made."""
    cm = MagicMock()
    cm.__aenter__ = AsyncMock(return_value=mock_fetcher)
    cm.__aexit__ = AsyncMock(return_value=False)
    return patch("iam_validator.core.policy_checks.AWSServiceFetcher", return_value=cm)


class TestCliParity:
    """The SDK must report what `iam-validator validate` reports for the same input."""

    async def test_validate_json_runs_structural_checks(self, mock_fetcher):
        policy = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Alow", "Action": "s3:GetObject", "Resource": "*"}],
        }
        with _patched_fetcher(mock_fetcher):
            result = await validate_json(policy)

        assert "invalid_effect" in {i.issue_type for i in result.issues}
        assert result.is_valid is False

    async def test_validate_json_forwards_raw_dict(self, valid_policy_dict):
        with patch(
            "iam_validator.sdk.shortcuts.validate_policies",
            new_callable=AsyncMock,
            return_value=[_make_result()],
        ) as spy:
            await validate_json(valid_policy_dict)

        [(_name, _policy, raw)] = spy.await_args.args[0]
        assert raw == valid_policy_dict

    async def test_unparseable_file_is_a_failed_result(self, tmp_path):
        broken = tmp_path / "broken.json"
        broken.write_text('{"Statement": [')
        result = await validate_file(broken)

        assert result.is_valid is False
        assert result.issues[0].issue_type == "policy_parse_error"

    async def test_directory_with_broken_file_is_not_valid(self, tmp_policy_dir):
        (tmp_policy_dir / "broken.json").write_text("{")
        with patch(
            "iam_validator.sdk.shortcuts.validate_policies",
            new_callable=AsyncMock,
            return_value=[_make_result(policy_file="p1.json"), _make_result(policy_file="p2.json")],
        ):
            results = await validate_directory(tmp_policy_dir)
            assert await quick_validate(str(tmp_policy_dir)) is False

        assert len(results) == 3
        assert [r.is_valid for r in results] == [True, True, False]

    async def test_cli_options_are_forwarded(self, tmp_policy_file, tmp_path):
        with patch(
            "iam_validator.sdk.shortcuts.validate_policies",
            new_callable=AsyncMock,
            return_value=[_make_result()],
        ) as spy:
            await validate_file(
                tmp_policy_file,
                aws_services_dir=str(tmp_path),
                custom_checks_dir=str(tmp_path),
                allow_config_custom_checks=True,
            )

        kwargs = spy.await_args.kwargs
        assert kwargs["aws_services_dir"] == str(tmp_path)
        assert kwargs["custom_checks_dir"] == str(tmp_path)
        assert kwargs["allow_config_custom_checks"] is True
