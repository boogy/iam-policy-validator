"""The streaming path must resolve policy_type and offline mode exactly as the batch path does."""

import inspect
from argparse import Namespace
from unittest.mock import AsyncMock, patch

import pytest

from iam_validator.commands.validate import ValidateCommand


def _streaming_source() -> str:
    return inspect.getsource(ValidateCommand._execute_streaming)


def test_streaming_passes_aws_services_dir():
    assert "aws_services_dir" in _streaming_source()


def test_streaming_does_not_force_identity_policy():
    assert '"IDENTITY_POLICY"' not in _streaming_source()


def _streaming_args(tmp_path, **overrides) -> Namespace:
    policy = tmp_path / "trust.json"
    policy.write_text(
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
        '"Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
    )
    defaults = dict(
        paths=[str(policy)],
        no_recursive=True,
        stdin=False,
        config=None,
        custom_checks_dir=None,
        policy_type=None,
        aws_services_dir=None,
        allow_config_custom_checks=False,
        format="json",
        output=None,
        ci=False,
        github_review=False,
        github_comment=False,
        fail_on_warnings=False,
    )
    defaults.update(overrides)
    return Namespace(**defaults)


@pytest.mark.asyncio
async def test_streaming_passes_aws_services_dir_to_validate_policies(tmp_path):
    args = _streaming_args(tmp_path, aws_services_dir=str(tmp_path))
    spy = AsyncMock(return_value=[])
    with patch("iam_validator.commands.validate.validate_policies", spy):
        await ValidateCommand()._execute_streaming(args)

    assert spy.await_args.kwargs["aws_services_dir"] == str(tmp_path)


@pytest.mark.asyncio
async def test_streaming_leaves_policy_type_unresolved_without_the_flag(tmp_path):
    args = _streaming_args(tmp_path)
    spy = AsyncMock(return_value=[])
    with patch("iam_validator.commands.validate.validate_policies", spy):
        await ValidateCommand()._execute_streaming(args)

    assert spy.await_args.kwargs["policy_type"] is None


@pytest.mark.asyncio
async def test_streaming_and_batch_pass_the_same_keywords(tmp_path):
    args = _streaming_args(tmp_path, aws_services_dir=str(tmp_path))
    spy = AsyncMock(return_value=[])

    with patch("iam_validator.commands.validate.validate_policies", spy):
        await ValidateCommand()._execute_streaming(args)
    stream_kwargs = set(spy.await_args.kwargs)

    with patch("iam_validator.commands.validate.validate_policies", spy):
        await ValidateCommand().execute(args)
    batch_kwargs = set(spy.await_args.kwargs)

    assert stream_kwargs == batch_kwargs
