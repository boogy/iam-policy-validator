"""Tests for the validate command's stdin input path."""

import json
from argparse import Namespace
from unittest.mock import AsyncMock, patch

import pytest

from iam_validator.commands.validate import ValidateCommand

POLICY_JSON = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
    }
)


def _stdin_args() -> Namespace:
    return Namespace(
        stdin=True,
        paths=None,
        no_recursive=False,
        format="json",
        output=None,
        fail_on_warnings=False,
        github_comment=False,
    )


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
    policies = mock_validate.await_args.args[0]
    assert policies == [("stdin", json.loads(POLICY_JSON))]


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
    policies = mock_validate.await_args.args[0]
    assert policies == [("stdin", json.loads(POLICY_JSON))]
