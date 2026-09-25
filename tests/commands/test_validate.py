"""Tests for the validate command's stdin input path and parse-error handling."""

import json
from argparse import Namespace
from unittest.mock import AsyncMock, patch

import pytest

from iam_validator.commands.validate import ValidateCommand
from iam_validator.core import constants
from iam_validator.core.models import IAMPolicy, PolicyValidationResult

POLICY_JSON = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
    }
)


def _stdin_args(**overrides) -> Namespace:
    defaults = dict(
        stdin=True,
        paths=None,
        no_recursive=False,
        format="json",
        output=None,
        fail_on_warnings=False,
        github_comment=False,
    )
    defaults.update(overrides)
    return Namespace(**defaults)


def _path_args(paths: list[str], **overrides) -> Namespace:
    defaults = dict(
        stdin=False,
        paths=paths,
        no_recursive=True,
        format="json",
        output=None,
        fail_on_warnings=False,
        github_comment=False,
        github_review=False,
        config=None,
        custom_checks_dir=None,
        policy_type=None,
        aws_services_dir=None,
        allow_config_custom_checks=False,
        ci=False,
    )
    defaults.update(overrides)
    return Namespace(**defaults)


def _assert_stdin_policy(policies) -> None:
    assert len(policies) == 1
    name, policy, raw = policies[0]
    assert name == "stdin"
    assert isinstance(policy, IAMPolicy)
    # The raw dict is forwarded so policy_structure's document-level checks run.
    assert raw == json.loads(POLICY_JSON)


def _valid_result(policy_file: str) -> PolicyValidationResult:
    return PolicyValidationResult(policy_file=policy_file, is_valid=True)


@pytest.mark.asyncio
async def test_stdin_with_utf8_bom_loads(monkeypatch):
    """A UTF-8 BOM on stdin must not be treated as invalid JSON."""
    monkeypatch.setattr("sys.stdin.read", lambda: "\ufeff" + POLICY_JSON)

    with patch(
        "iam_validator.commands.validate.validate_policies",
        new=AsyncMock(return_value=[]),
    ) as mock_validate:
        exit_code = await ValidateCommand()._execute_batch(_stdin_args())

    assert exit_code == 0
    _assert_stdin_policy(mock_validate.await_args.args[0])


@pytest.mark.asyncio
async def test_stdin_without_bom_still_loads(monkeypatch):
    """Plain UTF-8 stdin content (no BOM) must keep working."""
    monkeypatch.setattr("sys.stdin.read", lambda: POLICY_JSON)

    with patch(
        "iam_validator.commands.validate.validate_policies",
        new=AsyncMock(return_value=[]),
    ) as mock_validate:
        exit_code = await ValidateCommand()._execute_batch(_stdin_args())

    assert exit_code == 0
    _assert_stdin_policy(mock_validate.await_args.args[0])


@pytest.mark.asyncio
async def test_stdin_invalid_json_is_flagged_and_fails(monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin.read", lambda: "{not json")

    with patch(
        "iam_validator.commands.validate.validate_policies",
        new=AsyncMock(return_value=[]),
    ):
        exit_code = await ValidateCommand()._execute_batch(_stdin_args())

    assert exit_code == 1
    assert constants.PARSE_ERROR_ISSUE_TYPE in capsys.readouterr().out


@pytest.mark.asyncio
async def test_stdin_in_streaming_mode_does_not_crash(monkeypatch):
    """CI auto-enables streaming; --stdin has no paths to stream and must fall back to batch."""
    monkeypatch.setattr("sys.stdin.read", lambda: POLICY_JSON)

    with patch(
        "iam_validator.commands.validate.validate_policies",
        new=AsyncMock(return_value=[]),
    ) as mock_validate:
        exit_code = await ValidateCommand()._execute_streaming(_stdin_args())

    assert exit_code == 0
    _assert_stdin_policy(mock_validate.await_args.args[0])


@pytest.mark.asyncio
@pytest.mark.parametrize("streaming", [False, True])
async def test_broken_file_is_flagged_while_others_are_validated(tmp_path, capsys, streaming):
    good = tmp_path / "good.json"
    good.write_text(POLICY_JSON)
    broken = tmp_path / "broken.json"
    broken.write_text('{"Version": "2012-10-17", "Statement": [')

    async def fake_validate(policies, **_kwargs):
        return [_valid_result(item[0]) for item in policies]

    command = ValidateCommand()
    run = command._execute_streaming if streaming else command._execute_batch
    with patch("iam_validator.commands.validate.validate_policies", new=AsyncMock(side_effect=fake_validate)):
        exit_code = await run(_path_args([str(tmp_path)]))

    assert exit_code == 1
    report = json.loads(capsys.readouterr().out)
    by_file = {r["policy_file"]: r for r in report["results"]}
    assert by_file[str(good)]["is_valid"] is True
    assert by_file[str(broken)]["is_valid"] is False
    assert by_file[str(broken)]["issues"][0]["issue_type"] == constants.PARSE_ERROR_ISSUE_TYPE
    assert report["invalid_policies"] == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("streaming", [False, True])
async def test_only_broken_files_still_reports_them(tmp_path, capsys, streaming):
    broken = tmp_path / "broken.json"
    broken.write_text("[]")

    command = ValidateCommand()
    run = command._execute_streaming if streaming else command._execute_batch
    with patch("iam_validator.commands.validate.validate_policies", new=AsyncMock(return_value=[])):
        exit_code = await run(_path_args([str(broken)]))

    assert exit_code == 1
    report = json.loads(capsys.readouterr().out)
    assert [r["policy_file"] for r in report["results"]] == [str(broken)]
